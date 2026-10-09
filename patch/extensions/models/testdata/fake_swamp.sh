#!/bin/sh
# Test double for the `swamp` CLI, used only by patch_fleet_test.ts.
# Pre-flight checks run it as SWAMP_BIN; the test's `runModel` adapter runs it with
# the same CLI arguments for methods. So no host, ssh link or Proxmox node is needed.
#
# Behavior comes from FAKE_SWAMP_* environment variables. Each holds the exact text
# to print on stdout (normally a JSON document).
#
#   model method run M script ...     prints FAKE_SWAMP_SCRIPT_1; the 2nd call prints
#                                     FAKE_SWAMP_SCRIPT_2 (or _1 when _2 is unset);
#                                     exit FAKE_SWAMP_SCRIPT_RC (0). Except:
#       a health batch (the script, or the base64 payload it pipes to `base64 -d`,
#       contains "@@PATCH-HC")    prints FAKE_SWAMP_HC, exit FAKE_SWAMP_HC_RC (0)
#       a CT collector batch (the script contains "@@PATCH-CT")
#                                 prints FAKE_SWAMP_PCT, exit FAKE_SWAMP_PCT_RC (0)
#   model method run M exec ...       prints FAKE_SWAMP_EXEC, exit FAKE_SWAMP_EXEC_RC (0), except:
#       command with "compose ps -q"      prints FAKE_SWAMP_PS
#       command with "Config.Image"       prints FAKE_SWAMP_INSPECT_1, then _2
#       command with "dpkg-query"         prints FAKE_SWAMP_PKGS_1, then _2
#   model method run M listVmSnapshots ...  prints FAKE_SWAMP_VMSNAPS, exit FAKE_SWAMP_VMSNAPS_RC (0)
#   model method run M listGuests ...       prints FAKE_SWAMP_GUESTS, exit FAKE_SWAMP_GUESTS_RC (0)
#   model method run M safeUpdate ... (the app source's updater; the test reads the call log)
#       with "snapshot:json=false" and FAKE_SWAMP_APP_REJECT_SNAPSHOT set: prints swamp's
#           "Unknown method input(s): snapshot" error on stderr, exit 1
#       else exit FAKE_SWAMP_APP_RC (0), with FAKE_SWAMP_APP_ERR on stderr when it is not 0
#   model method run M <other> ...    prints nothing, exit FAKE_SWAMP_METHOD_RC (0)
#
# FAKE_SWAMP_MODEL_GET / FAKE_SWAMP_GET_RC are not read here: the model reads
# definitions in-process, and the test's stub definitionRepository reads them.
#
# When FAKE_SWAMP_CALL_LOG names a file, every `model method run` call appends one line to
# it: "<model> <method> <arguments...>" (newlines in arguments become spaces). Tests read
# it to see what the model called.
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

if [ "$1" = "model" ] && [ "$2" = "method" ] && [ "$3" = "run" ]; then
  if [ -n "${FAKE_SWAMP_CALL_LOG-}" ]; then
    # One line per call: newlines inside an argument (a multi-line script) become spaces.
    { printf '%s' "$4 $5 $*" | tr '\n' ' '; printf '\n'; } >> "$FAKE_SWAMP_CALL_LOG"
  fi
  case "$5" in
    safeUpdate)
      case "$*" in
        *"snapshot:json=false"*)
          if [ -n "${FAKE_SWAMP_APP_REJECT_SNAPSHOT-}" ]; then
            printf '%s\n' '{"error": "Unknown method input(s): snapshot. Valid inputs are: keepSnapshot", "code": "validation_failed"}' >&2
            exit 1
          fi
          ;;
      esac
      if [ "${FAKE_SWAMP_APP_RC:-0}" -ne 0 ]; then
        printf '%s\n' "${FAKE_SWAMP_APP_ERR-}" >&2
      fi
      exit "${FAKE_SWAMP_APP_RC:-0}"
      ;;
    script)
      body=""
      for a in "$@"; do
        case "$a" in script=*) body="${a#script=}" ;; esac
      done
      # A CT health batch is shipped as base64 into `pct exec`: decode it to look inside.
      decoded=""
      case "$body" in
        *"| base64 -d"*)
          b64=$(printf '%s\n' "$body" | sed -n "s#.*echo '\([A-Za-z0-9+/=]*\)' | base64 -d.*#\1#p" | head -n 1)
          decoded=$(printf '%s' "$b64" | base64 -d 2>/dev/null)
          ;;
      esac
      case "$body$decoded" in
        *"@@PATCH-HC"*)
          printf '%s\n' "${FAKE_SWAMP_HC-}"
          exit "${FAKE_SWAMP_HC_RC:-0}"
          ;;
        *"@@PATCH-CT"*)
          printf '%s\n' "${FAKE_SWAMP_PCT-}"
          exit "${FAKE_SWAMP_PCT_RC:-0}"
          ;;
      esac
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
    listGuests)
      printf '%s\n' "${FAKE_SWAMP_GUESTS-}"
      exit "${FAKE_SWAMP_GUESTS_RC:-0}"
      ;;
    *)
      exit "${FAKE_SWAMP_METHOD_RC:-0}"
      ;;
  esac
fi

echo "fake swamp: unsupported arguments: $*" >&2
exit 2
