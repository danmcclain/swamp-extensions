#!/bin/sh
# Test double for the `swamp` CLI, used only by patch_fleet_test.ts.
# The test sets SWAMP_BIN to this file. The model then runs it instead of the real
# swamp binary, so no host, ssh link or Proxmox node is needed.
#
# Behavior comes from FAKE_SWAMP_* environment variables. Each holds the exact text
# to print on stdout (normally a JSON document).
#
#   model get <name> ...              prints FAKE_SWAMP_MODEL_GET, exit FAKE_SWAMP_GET_RC (0)
#   data get <model> <name> ...       prints FAKE_SWAMP_DATA_GET
#   model method run M script ...     prints FAKE_SWAMP_SCRIPT_1; the 2nd call prints
#                                     FAKE_SWAMP_SCRIPT_2 (or _1 when _2 is unset)
#   model method run M exec ...       prints FAKE_SWAMP_EXEC, except:
#       command with "compose ps -q"      prints FAKE_SWAMP_PS
#       command with "Config.Image"       prints FAKE_SWAMP_INSPECT_1, then _2
#       command with "dpkg-query"         prints FAKE_SWAMP_PKGS_1, then _2
#   model method run M listVmSnapshots ...  prints FAKE_SWAMP_VMSNAPS, exit FAKE_SWAMP_VMSNAPS_RC (0)
#   model method run M <other> ...    prints nothing, exit FAKE_SWAMP_METHOD_RC (0)
#
# The "then _2" sequences keep a marker file named after FAKE_SWAMP_STATE in
# ${TMPDIR:-/tmp}. The second call removes the marker. The test calls
# `fake_swamp.sh cleanup` after each case to remove any marker that is left.

state_dir="${TMPDIR:-/tmp}"

# seq_out KIND: print FAKE_SWAMP_<KIND>_1 on the first call, _2 on the second.
seq_out() {
  kind="$1"
  marker="${state_dir%/}/fake-swamp-${FAKE_SWAMP_STATE:-none}-$kind"
  if [ -e "$marker" ]; then
    rm -f "$marker"
    eval "second=\${FAKE_SWAMP_${kind}_2-__unset__}"
    if [ "$second" != "__unset__" ]; then
      printf '%s\n' "$second"
      return
    fi
  else
    : > "$marker"
  fi
  eval "first=\${FAKE_SWAMP_${kind}_1-}"
  printf '%s\n' "$first"
}

if [ "$1" = "cleanup" ]; then
  # Called by the test after each case: drop this case's marker files.
  rm -f "${state_dir%/}/fake-swamp-${FAKE_SWAMP_STATE:-none}-"*
  exit 0
fi

if [ "$1" = "model" ] && [ "$2" = "get" ]; then
  printf '%s\n' "${FAKE_SWAMP_MODEL_GET-}"
  exit "${FAKE_SWAMP_GET_RC:-0}"
fi

if [ "$1" = "data" ] && [ "$2" = "get" ]; then
  printf '%s\n' "${FAKE_SWAMP_DATA_GET-}"
  exit 0
fi

if [ "$1" = "model" ] && [ "$2" = "method" ] && [ "$3" = "run" ]; then
  case "$5" in
    script)
      seq_out SCRIPT
      exit "${FAKE_SWAMP_SCRIPT_RC:-0}"
      ;;
    exec)
      cmd=""
      for a in "$@"; do
        case "$a" in command=*) cmd="$a" ;; esac
      done
      case "$cmd" in
        *"compose ps -q"*) printf '%s\n' "${FAKE_SWAMP_PS-}" ;;
        *"Config.Image"*) seq_out INSPECT ;;
        *"dpkg-query"*) seq_out PKGS ;;
        *) printf '%s\n' "${FAKE_SWAMP_EXEC-}" ;;
      esac
      exit "${FAKE_SWAMP_EXEC_RC:-0}"
      ;;
    listVmSnapshots)
      printf '%s\n' "${FAKE_SWAMP_VMSNAPS-}"
      exit "${FAKE_SWAMP_VMSNAPS_RC:-0}"
      ;;
    *)
      exit "${FAKE_SWAMP_METHOD_RC:-0}"
      ;;
  esac
fi

echo "fake swamp: unsupported arguments: $*" >&2
exit 2
