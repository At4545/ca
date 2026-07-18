#!/usr/bin/env bash
#
# delete_openshift_users.sh
# -------------------------------------------------------------------
# Interactive script to delete OpenShift user + identity objects
# across multiple clusters.
#
# Features:
#   - JSON-based cluster inventory (name, api_url, token)
#   - Token field initially empty
#   - First-time login via: oc login --web --server=<api_url>
#   - Token extraction via: oc whoami -t
#   - Token saved back into the JSON file
#   - User list from TXT or CSV
#   - Dry-run mode by default
#   - Per-cluster confirmation before deletion
#   - Identity auto-discovery from: oc get user <user> -o json
#   - Deletes identities first, then the user
#   - Audit log generation
#   - Works on Linux and Git Bash (Windows)
#
# Requirements: oc, jq, awk, sed
# -------------------------------------------------------------------

set -o pipefail

SCRIPT_NAME="$(basename "$0")"
LOG_FILE="user_identity_delete_$(date +%Y%m%d_%H%M%S).log"
TMP_JSON_FILE="clusters.tmp.json"

CLUSTER_JSON=""
USER_FILE=""
DRY_RUN="true"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

log() {
    local level="$1"
    local msg="$2"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}

info()    { log "INFO" "$1"; }
warn()    { log "WARN" "${YELLOW}$1${NC}"; }
error()   { log "ERROR" "${RED}$1${NC}"; }
success() { log "SUCCESS" "${GREEN}$1${NC}"; }

print_header() {
    echo
    echo "=========================================================="
    echo " OpenShift User and Identity Cleanup - Interactive Script "
    echo "=========================================================="
    echo
}

check_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error "Required command not found: $cmd"
        exit 1
    fi
}

validate_prerequisites() {
    info "Validating prerequisites..."
    check_command "oc"
    check_command "jq"
    check_command "awk"
    check_command "sed"
    success "All required commands are available."
}

prompt_inputs() {
    read -r -p "Enter cluster JSON file path: " CLUSTER_JSON
    read -r -p "Enter user list file path TXT/CSV: " USER_FILE

    if [[ ! -f "$CLUSTER_JSON" ]]; then
        error "Cluster JSON file not found: $CLUSTER_JSON"
        exit 1
    fi

    if [[ ! -f "$USER_FILE" ]]; then
        error "User file not found: $USER_FILE"
        exit 1
    fi

    if ! jq empty "$CLUSTER_JSON" >/dev/null 2>&1; then
        error "Invalid JSON file: $CLUSTER_JSON"
        exit 1
    fi

    echo
    echo "Choose execution mode:"
    echo "1. Dry run only - no deletion"
    echo "2. Actual delete"
    read -r -p "Enter choice [1/2]: " mode_choice

    case "$mode_choice" in
        1)
            DRY_RUN="true"
            warn "Running in DRY-RUN mode. No users or identities will be deleted."
            ;;
        2)
            DRY_RUN="false"
            warn "Running in ACTUAL DELETE mode."
            read -r -p "Type DELETE to confirm actual deletion mode: " confirm_delete
            if [[ "$confirm_delete" != "DELETE" ]]; then
                error "Confirmation failed. Exiting."
                exit 1
            fi
            ;;
        *)
            error "Invalid choice."
            exit 1
            ;;
    esac
}

load_users() {
    local file="$1"

    if [[ "$file" == *.csv ]]; then
        awk -F',' '
        NR == 1 {
            header=tolower($1)
            gsub(/^[ \t"]+|[ \t"]+$/, "", header)
            if (header == "user" || header == "username" || header == "email") {
                next
            }
        }
        {
            user=$1
            gsub(/^[ \t"]+|[ \t"]+$/, "", user)
            if (user != "") print user
        }
        ' "$file" | sort -u
    else
        sed 's/\r$//' "$file" | awk '
        {
            user=$0
            gsub(/^[ \t]+|[ \t]+$/, "", user)
            if (user != "" && user !~ /^#/) print user
        }
        ' | sort -u
    fi
}

update_cluster_token() {
    local cluster_name="$1"
    local token="$2"

    jq \
      --arg cname "$cluster_name" \
      --arg token "$token" \
      '(.clusters[] | select(.name == $cname) | .token) = $token' \
      "$CLUSTER_JSON" > "$TMP_JSON_FILE"

    if [[ $? -ne 0 ]]; then
        error "Failed to update token in JSON for cluster: $cluster_name"
        rm -f "$TMP_JSON_FILE"
        return 1
    fi

    mv "$TMP_JSON_FILE" "$CLUSTER_JSON"
    chmod 600 "$CLUSTER_JSON" 2>/dev/null || true

    success "Token updated in JSON for cluster: $cluster_name"
}

oc_login_with_token() {
    local cluster_name="$1"
    local api_url="$2"
    local token="$3"

    if [[ -z "$token" || "$token" == "null" ]]; then
        return 1
    fi

    info "Trying token login for cluster: $cluster_name"

    oc login --token="$token" --server="$api_url" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        success "Token login successful for cluster: $cluster_name"
        return 0
    fi

    warn "Token login failed or token expired for cluster: $cluster_name"
    return 1
}

oc_login_web_and_save_token() {
    local cluster_name="$1"
    local api_url="$2"

    echo
    warn "Web login required for cluster: $cluster_name"
    echo "Command to be executed:"
    echo "oc login --web --server=$api_url"
    echo

    read -r -p "Press Enter to start web login for $cluster_name..."

    oc login --web --server="$api_url"
    if [[ $? -ne 0 ]]; then
        error "Web login failed for cluster: $cluster_name"
        return 1
    fi

    local new_token
    new_token="$(oc whoami -t 2>/dev/null)"

    if [[ -z "$new_token" ]]; then
        error "Could not extract token using oc whoami -t for cluster: $cluster_name"
        return 1
    fi

    update_cluster_token "$cluster_name" "$new_token"
    return $?
}

ensure_cluster_login() {
    local cluster_name="$1"
    local api_url="$2"
    local token="$3"

    if oc_login_with_token "$cluster_name" "$api_url" "$token"; then
        return 0
    fi

    oc_login_web_and_save_token "$cluster_name" "$api_url"
    return $?
}

delete_user_and_identities() {
    local cluster_name="$1"
    local user="$2"

    echo
    info "Processing user [$user] on cluster [$cluster_name]"

    if ! oc get user "$user" >/dev/null 2>&1; then
        warn "User not found in cluster [$cluster_name]: $user. Skipping."
        return 0
    fi

    local identities
    identities="$(oc get user "$user" -o json 2>/dev/null | jq -r '.identities[]?' 2>/dev/null)"

    if [[ -z "$identities" ]]; then
        warn "No identities found for user [$user] in cluster [$cluster_name]."
    else
        info "Identities found for user [$user]:"
        echo "$identities" | while read -r identity; do
            [[ -z "$identity" ]] && continue
            echo "  - $identity" | tee -a "$LOG_FILE"
        done
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        warn "[DRY-RUN] Would delete identities for user: $user"
        if [[ -n "$identities" ]]; then
            echo "$identities" | while read -r identity; do
                [[ -z "$identity" ]] && continue
                warn "[DRY-RUN] oc delete identity \"$identity\""
            done
        fi
        warn "[DRY-RUN] Would delete user: $user"
        warn "[DRY-RUN] oc delete user \"$user\""
        return 0
    fi

    if [[ -n "$identities" ]]; then
        echo "$identities" | while read -r identity; do
            [[ -z "$identity" ]] && continue

            info "Deleting identity [$identity] for user [$user]"
            oc delete identity "$identity" --ignore-not-found=true

            if [[ $? -eq 0 ]]; then
                success "Deleted identity [$identity]"
            else
                error "Failed to delete identity [$identity]"
            fi
        done
    fi

    info "Deleting user [$user]"
    oc delete user "$user" --ignore-not-found=true

    if [[ $? -eq 0 ]]; then
        success "Deleted user [$user]"
    else
        error "Failed to delete user [$user]"
        return 1
    fi

    return 0
}

process_cluster() {
    local cluster_index="$1"

    local cluster_name
    local api_url
    local token

    cluster_name="$(jq -r ".clusters[$cluster_index].name" "$CLUSTER_JSON")"
    api_url="$(jq -r ".clusters[$cluster_index].api_url" "$CLUSTER_JSON")"
    token="$(jq -r ".clusters[$cluster_index].token" "$CLUSTER_JSON")"

    if [[ -z "$cluster_name" || "$cluster_name" == "null" ]]; then
        error "Invalid cluster name at index: $cluster_index"
        return 1
    fi

    if [[ -z "$api_url" || "$api_url" == "null" ]]; then
        error "Invalid API URL for cluster: $cluster_name"
        return 1
    fi

    echo
    echo "----------------------------------------------------------"
    echo "Cluster: $cluster_name"
    echo "API URL: $api_url"
    echo "----------------------------------------------------------"

    read -r -p "Do you want to process this cluster? [y/N]: " process_choice
    case "$process_choice" in
        y|Y|yes|YES)
            ;;
        *)
            warn "Skipping cluster: $cluster_name"
            return 0
            ;;
    esac

    ensure_cluster_login "$cluster_name" "$api_url" "$token"
    if [[ $? -ne 0 ]]; then
        error "Skipping cluster due to login failure: $cluster_name"
        return 1
    fi

    local current_user
    current_user="$(oc whoami 2>/dev/null)"
    info "Logged in to [$cluster_name] as [$current_user]"

    local users
    users="$(load_users "$USER_FILE")"

    if [[ -z "$users" ]]; then
        error "No users found in input file: $USER_FILE"
        return 1
    fi

    echo
    info "Users to process:"
    echo "$users" | while read -r u; do
        echo "  - $u"
    done

    echo
    if [[ "$DRY_RUN" == "false" ]]; then
        warn "Actual deletion mode is enabled for cluster: $cluster_name"
        read -r -p "Type cluster name [$cluster_name] to confirm deletion on this cluster: " cluster_confirm
        if [[ "$cluster_confirm" != "$cluster_name" ]]; then
            error "Cluster confirmation failed. Skipping cluster: $cluster_name"
            return 1
        fi
    fi

    echo "$users" | while read -r user; do
        [[ -z "$user" ]] && continue
        delete_user_and_identities "$cluster_name" "$user"
    done

    success "Completed processing cluster: $cluster_name"
}

main() {
    print_header
    validate_prerequisites
    prompt_inputs

    local cluster_count
    cluster_count="$(jq '.clusters | length' "$CLUSTER_JSON")"

    if [[ "$cluster_count" -eq 0 ]]; then
        error "No clusters found in JSON file."
        exit 1
    fi

    info "Total clusters found: $cluster_count"
    info "Log file: $LOG_FILE"

    for ((i = 0; i < cluster_count; i++)); do
        process_cluster "$i"
    done

    echo
    success "Script execution completed."
    info "Review log file: $LOG_FILE"
}

main "$@"
