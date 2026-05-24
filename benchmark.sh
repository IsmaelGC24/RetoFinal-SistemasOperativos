#!/usr/bin/env bash
# =============================================================================
# benchmark.sh - Benchmark del pipeline RLE -> RC4
# Reto Final: El Triangulo de Hierro (Espacio, Tiempo y Seguridad)
#
# Escenarios medidos:
#   A. Clasico plano:
#      cp archivo_50MB out_plain.dat
#   B. Solo compresion:
#      ./editor compress-only out.rle < archivo_50MB
#   C. Compresion + encriptacion:
#      EDITOR_KEY="$KEY" ./editor write out.enc < archivo_50MB
#   D. Solo cifrado sobre buffer ya comprimido:
#      EDITOR_KEY="$KEY" ./editor encrypt-only out.rc4 < out.rle
#
# Uso:
#   chmod +x benchmark.sh
#   ./benchmark.sh
# =============================================================================

set -euo pipefail

EDITOR_BIN="${EDITOR_BIN:-./editor}"
KEY="${EDITOR_KEY_BENCH:-benchmark_reto_final_eafit}"
TAMANIO_MB="${TAMANIO_MB:-50}"
TAMANIO_BYTES=$((TAMANIO_MB * 1024 * 1024))
WORKDIR="${TMPDIR:-/tmp}/reto_so_benchmark_$$"
ARCHIVO_PRUEBA="$WORKDIR/archivo_50MB.dat"
RESULTS="$WORKDIR/results.tsv"

OUT_PLAIN="$WORKDIR/out_plain.dat"
OUT_RLE="$WORKDIR/out.rle"
OUT_ENC="$WORKDIR/out.enc"
OUT_RC4="$WORKDIR/out.rc4"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

title() {
    printf '\n== %s ==\n' "$1"
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Error: falta "%s". En Ubuntu/Debian: sudo apt install %s\n' "$1" "$2" >&2
        exit 1
    fi
}

file_size() {
    stat -c '%s' "$1"
}

parse_time_value() {
    local key="$1"
    local file="$2"
    awk -v key="$key" '{
        for (i = 1; i <= NF; i++) {
            split($i, p, ":")
            if (p[1] == key) {
                print p[2]
            }
        }
    }' "$file"
}

count_syscall() {
    local syscall="$1"
    local file="$2"
    grep -Ec "(^|[[:space:]])${syscall}\\(" "$file" || true
}

count_data_writes() {
    local file="$1"
    awk '/(^|[[:space:]])write\(/ && $0 !~ /write\(2,/ { count++ } END { print count + 0 }' "$file"
}

run_case() {
    local id="$1"
    local label="$2"
    local outfile="$3"
    shift 3

    local time_file="$WORKDIR/${id}.time"
    local trace_file="$WORKDIR/${id}.strace"
    local log_file="$WORKDIR/${id}.log"

    title "$id. $label"
    if ! /usr/bin/time -f 'WALL:%e USER:%U SYS:%S MEM:%M' -o "$time_file" \
        strace -qq -f -e trace=read,write -o "$trace_file" "$@" 2>"$log_file"; then
        cat "$log_file" >&2
        printf 'Error: fallo el escenario %s\n' "$id" >&2
        exit 1
    fi

    local size wall user sys mem reads writes
    size="$(file_size "$outfile")"
    wall="$(parse_time_value WALL "$time_file")"
    user="$(parse_time_value USER "$time_file")"
    sys="$(parse_time_value SYS "$time_file")"
    mem="$(parse_time_value MEM "$time_file")"
    reads="$(count_syscall read "$trace_file")"
    writes="$(count_data_writes "$trace_file")"

    printf 'Salida: %s bytes | wall=%ss user=%ss sys=%ss mem=%s KB | read()=%s write()=%s\n' \
        "$size" "$wall" "$user" "$sys" "$mem" "$reads" "$writes"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$label" "$size" "$wall" "$user" "$sys" "$mem" "$reads" "$writes" >> "$RESULTS"
}

verificar_dependencias() {
    require_cmd python3 python3
    require_cmd strace strace
    require_cmd stat coreutils

    if [ ! -x /usr/bin/time ]; then
        printf 'Error: falta GNU time. En Ubuntu/Debian: sudo apt install time\n' >&2
        exit 1
    fi

    if [ ! -x "$EDITOR_BIN" ]; then
        printf 'Error: no encuentro el binario "%s". Ejecuta: make\n' "$EDITOR_BIN" >&2
        exit 1
    fi
}

generar_archivo_prueba() {
    mkdir -p "$WORKDIR"
    : > "$RESULTS"

    title "Generando archivo de prueba (${TAMANIO_MB} MB)"
    python3 - "$TAMANIO_BYTES" "$ARCHIVO_PRUEBA" <<'PY'
import sys

target = int(sys.argv[1])
path = sys.argv[2]

# Datos binarios estructurados con runs largos: un caso favorable y defendible
# para RLE, similar a registros con padding/campos fijos.
chunk = bytes([0x00]) * 2048
chunk += bytes([0x41]) * 1024
chunk += bytes([0xff]) * 512
chunk += bytes([0x20]) * 512

with open(path, "wb") as f:
    remaining = target
    while remaining > 0:
        part = chunk[:remaining]
        f.write(part)
        remaining -= len(part)
PY
    printf 'Archivo base: %s bytes en %s\n' "$(file_size "$ARCHIVO_PRUEBA")" "$ARCHIVO_PRUEBA"
}

tabla_final() {
    title "Tabla final - El Triangulo de Hierro"
    python3 - "$RESULTS" "$TAMANIO_BYTES" <<'PY'
import sys

results_path = sys.argv[1]
original = int(sys.argv[2])

rows = []
with open(results_path, encoding="utf-8") as f:
    for line in f:
        ident, label, size, wall, user, sys_cpu, mem, reads, writes = line.rstrip("\n").split("\t")
        size = int(size)
        reduction = (1 - size / original) * 100 if original else 0
        rows.append({
            "id": ident,
            "label": label,
            "size": size,
            "reduction": reduction,
            "wall": float(wall),
            "user": float(user),
            "sys": float(sys_cpu),
            "mem": int(mem),
            "reads": int(reads),
            "writes": int(writes),
        })

headers = [
    "Escenario",
    "Tamano transmitido I/O",
    "Reduccion I/O",
    "CPU User",
    "CPU System",
    "Wall-clock",
    "Memoria max",
    "read()",
    "write()",
]

table = []
for r in rows:
    table.append([
        f"{r['id']}. {r['label']}",
        f"{r['size']:,} bytes",
        "0.0%" if r["id"] == "A" else f"{r['reduction']:.1f}%",
        f"{r['user']:.3f}s",
        f"{r['sys']:.3f}s",
        f"{r['wall']:.3f}s",
        f"{r['mem']:,} KB",
        str(r["reads"]),
        str(r["writes"]),
    ])

widths = [max(len(str(x)) for x in col) for col in zip(headers, *table)]

def print_row(values):
    print("| " + " | ".join(str(v).ljust(w) for v, w in zip(values, widths)) + " |")

print_row(headers)
print("|-" + "-|-".join("-" * w for w in widths) + "-|")
for row in table:
    print_row(row)

by_id = {r["id"]: r for r in rows}
a = by_id["A"]
b = by_id["B"]
c = by_id["C"]
d = by_id["D"]

print()
print("Conclusion: espacio, tiempo y seguridad")
print(f"- Espacio: B reduce el I/O en {b['reduction']:.1f}% y C mantiene esa reduccion despues de cifrar.")
print(f"- Tiempo: C paga CPU user adicional frente a A ({c['user']:.3f}s vs {a['user']:.3f}s), pero escribe muchos menos bytes.")
print(f"- Seguridad: A y B no protegen datos en reposo; C cifra el resultado comprimido con RC4.")
print(f"- Aislamiento: D mide RC4 sobre el buffer ya comprimido ({d['size']:,} bytes), separando el costo de cifrado del costo RLE.")
PY
}

main() {
    verificar_dependencias
    generar_archivo_prueba

    run_case "A" "Clasico plano cp" "$OUT_PLAIN" \
        cp "$ARCHIVO_PRUEBA" "$OUT_PLAIN"

    run_case "B" "Solo compresion RLE" "$OUT_RLE" \
        bash -c '"$1" compress-only "$2" < "$3"' bash "$EDITOR_BIN" "$OUT_RLE" "$ARCHIVO_PRUEBA"

    run_case "C" "Compresion + encriptacion" "$OUT_ENC" \
        bash -c 'EDITOR_KEY="$1" "$2" write "$3" < "$4"' bash "$KEY" "$EDITOR_BIN" "$OUT_ENC" "$ARCHIVO_PRUEBA"

    run_case "D" "Solo cifrado sobre out.rle" "$OUT_RC4" \
        bash -c 'EDITOR_KEY="$1" "$2" encrypt-only "$3" < "$4"' bash "$KEY" "$EDITOR_BIN" "$OUT_RC4" "$OUT_RLE"

    tabla_final
}

main "$@"
