#!/usr/bin/osascript -l JavaScript
//
//  compare-performance.js
//  Mac Monitor
//
//  Compares two results files from test-performance.sh, benchmark by
//  benchmark: the median time per operation in each, and the change. A change
//  is called out only when it's larger than both files' noise: twice the
//  larger relative standard deviation of the two, and at least 3%.
//
//  The files can come from two commits on one Mac (a regression check) or one
//  commit on two Macs (an M1 Max against an M5): the header shows each file's
//  Mac, macOS and build, and warns when a build wasn't optimized or a run
//  started throttled.
//
//  Created by Brandon Dalton on 11/5/26.
//
//  Usage: compare-performance.js [--cpu] <before.json> <after.json>
//
//    --cpu  Compare CPU time rather than wall time.
//

ObjC.import("Foundation")

/**
 * Read a results file.
 *
 * @param {string} path - The file's path.
 * @returns {object} The parsed document.
 */
function readResults(path) {
    const error = $()
    const text = $.NSString.stringWithContentsOfFileEncodingError($(path).stringByStandardizingPath,
                                                                  $.NSUTF8StringEncoding, error)
    if (text.isNil()) throw new Error(`Can't read ${path}: ${error.localizedDescription.js}`)
    const document = JSON.parse(text.js)
    if (document.format !== 1) throw new Error(`${path} isn't a format 1 results file`)
    return document
}

/**
 * One line about the run a file holds.
 *
 * @param {string} label - "Before" or "After".
 * @param {object} document - The results file.
 * @returns {string[]} The line, and a warning for each reason its numbers are suspect.
 */
function describe(label, document) {
    const { machine, system, build } = document.environment
    const name = label.trim()
    const cores = machine.performance_cores == null ? `${machine.logical_cores} cores`
        : `${machine.performance_cores}P+${machine.efficiency_cores}E`
    const lines = [`${label}: ${machine.model} ${machine.chip} (${cores}), macOS ${system.version} (${system.build}), `
        + `Mac Monitor ${build.mac_monitor_version} ${build.commit || "?"}, ${build.configuration}`]
    if (!build.optimized) lines.push(`  ⚠️  ${name} is an unoptimized build: its times say little about the app`)
    if (system.thermal_state !== "nominal") lines.push(`  ⚠️  ${name} started ${system.thermal_state}ly throttled`)
    if (system.low_power_mode) lines.push(`  ⚠️  ${name} ran in Low Power Mode`)
    if (machine.translated) lines.push(`  ⚠️  ${name} ran under Rosetta`)
    return lines
}

/**
 * A time in the unit that reads best.
 *
 * @param {number} nanoseconds - The time.
 * @returns {string} The time, such as "10.123 µs".
 */
function time(nanoseconds) {
    if (nanoseconds >= 1e6) return `${(nanoseconds / 1e6).toFixed(3)} ms`
    return `${(nanoseconds / 1e3).toFixed(3)} µs`
}

/**
 * Compare the two files.
 *
 * @param {string[]} argv - The arguments.
 * @returns {string} The report, which osascript prints.
 */
function run(argv) {
    const metric = argv.includes("--cpu") ? "cpu_ns" : "wall_ns"
    const paths = argv.filter(argument => argument !== "--cpu")
    if (paths.length !== 2) return "Usage: compare-performance.js [--cpu] <before.json> <after.json>"
    const [before, after] = paths.map(readResults)
    const lines = [...describe("Before", before), ...describe("After ", after), ""]
    if (before.environment.machine.model !== after.environment.machine.model) {
        lines.push("Different Macs: the change is the hardware's (and macOS's) as much as the code's.", "")
    }

    const byName = results => new Map(results.map(result => [result.name, result]))
    const [old, now] = [byName(before.results), byName(after.results)]
    const names = [...new Set([...old.keys(), ...now.keys()])].sort()
    const width = Math.max(9, ...names.map(name => name.length))
    lines.push(`${"Benchmark".padEnd(width)}  ${"Before".padStart(12)}  ${"After".padStart(12)}  Change`)
    for (const name of names) {
        const [a, b] = [old.get(name), now.get(name)]
        if (!a || !b) {
            const only = a ? "before" : "after"
            lines.push(`${name.padEnd(width)}  only in ${only}`)
            continue
        }
        const [x, y] = [a[metric], b[metric]]
        const change = (y.median - x.median) / x.median
        const noise = Math.max(0.03, 2 * Math.max(x.stddev / x.mean || 0, y.stddev / y.mean || 0))
        const verdict = Math.abs(change) <= noise ? "~" : change < 0 ? "faster" : "slower"
        const percent = `${change >= 0 ? "+" : ""}${(change * 100).toFixed(1)}%`
        lines.push(`${name.padEnd(width)}  ${time(x.median).padStart(12)}  ${time(y.median).padStart(12)}  `
            + `${percent.padStart(7)} ${verdict} (per ${b.unit}, ±${(noise * 100).toFixed(0)}%)`)
    }
    return lines.join("\n")
}
