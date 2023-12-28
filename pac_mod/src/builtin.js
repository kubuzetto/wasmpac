// Refactored from:
// https://hg.mozilla.org/mozilla-central/raw-file/tip/netwerk/base/ascii_pac_utils.js
// noinspection JSUnusedGlobalSymbols,JSUnresolvedReference

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

function dnsDomainIs(host, domain) {
    let l = host.length - domain.length
    return l >= 0 && host.substring(l) === domain
}

function dnsDomainLevels(host) {
    return host.split(".").length - 1
}

function isValidIpAddress(ip) {
    let m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
    return m != null && m[1] <= 255 && m[2] <= 255 && m[3] <= 255 && m[4] <= 255
}

function convert_addr(ip) {
    let b = ip.split(".")
    return (b[3] & 0xff) | ((b[2] & 0xff) << 8) | ((b[1] & 0xff) << 16) | ((b[0] & 0xff) << 24)
}

function isPlainHostName(host) {
    return host.search("(\\.)|:") === -1
}

function isResolvable(host) {
    return dnsResolve(host) != null
}

function isInNet(ipaddr, pattern, maskstr) {
    if (!isValidIpAddress(pattern) || !isValidIpAddress(maskstr))
        return false
    if (!isValidIpAddress(ipaddr)) {
        ipaddr = dnsResolve(ipaddr)
        if (ipaddr == null) return false
    }
    let mask = convert_addr(maskstr)
    return (convert_addr(ipaddr) & mask) === (convert_addr(pattern) & mask)
}

function localHostOrDomainIs(host, hostdom) {
    return host === hostdom || hostdom.lastIndexOf(host + ".", 0) === 0
}

function shExpMatch(url, pattern) {
    return new RegExp("^" + pattern.replace(/\./g, "\\.").replace(/\*/g, ".*").replace(/\?/g, ".") + "$").test(url)
}

const wdays = {SUN: 0, MON: 1, TUE: 2, WED: 3, THU: 4, FRI: 5, SAT: 6}
const months = {JAN: 0, FEB: 1, MAR: 2, APR: 3, MAY: 4, JUN: 5, JUL: 6, AUG: 7, SEP: 8, OCT: 9, NOV: 10, DEC: 11}

function weekdayRange() {
    let n = arguments.length
    if (n !== 0) {
        let isGMT = arguments[n - 1] === "GMT"
        if (isGMT && --n === 0) return false
        let dt = new Date()
        let d = isGMT ? dt.getUTCDay() : dt.getDay()
        if (arguments[0] in wdays) {
            let st = wdays[arguments[0]]
            if (n === 1) return st === d
            if (arguments[1] in wdays) {
                let end = wdays[arguments[1]]
                return (st > end) ? (st <= d || d <= end) : (st <= d && d <= end)
            }
        }
    }
    return false
}

function dateRange() {
    let n = arguments.length
    if (n !== 0) {
        let isGMT = arguments[n - 1] === "GMT"
        if (isGMT && --n === 0) return false
        let dt = new Date()
        if (n === 1) {
            let m = parseInt(arguments[0])
            if (isGMT) {
                if (isNaN(m))
                    return arguments[0] in months && dt.getUTCMonth() === months[arguments[0]]
                else
                    return m < 32 ? dt.getUTCDate() === m : dt.getUTCFullYear() === m
            } else if (isNaN(m))
                return arguments[0] in months && dt.getMonth() === months[arguments[0]]
            else return m < 32 ? dt.getDate() === m : dt.getFullYear() === m
        }
        let year = dt.getFullYear()
        let st = new Date(year, 0, 1, 0, 0, 0)
        let end = new Date(year, 11, 31, 23, 59, 59)
        let adjustMonth = false
        let mid = n >> 1
        for (let i = 0; i < mid; i++) {
            let tmp = parseInt(arguments[i])
            if (isNaN(tmp)) st.setMonth(months[arguments[i]])
            else if (tmp < 32) {
                adjustMonth = n <= 2
                st.setDate(tmp)
            } else st.setFullYear(tmp)
        }
        for (let i = mid; i < n; i++) {
            let tmp = parseInt(arguments[i])
            if (isNaN(tmp)) end.setMonth(months[arguments[i]])
            else if (tmp < 32) end.setDate(tmp)
            else end.setFullYear(tmp)
        }
        if (adjustMonth) {
            st.setMonth(dt.getMonth())
            end.setMonth(dt.getMonth())
        }
        // noinspection DuplicatedCode
        if (isGMT) {
            let tmp = dt
            tmp.setFullYear(dt.getUTCFullYear())
            tmp.setMonth(dt.getUTCMonth())
            tmp.setDate(dt.getUTCDate())
            tmp.setHours(dt.getUTCHours())
            tmp.setMinutes(dt.getUTCMinutes())
            tmp.setSeconds(dt.getUTCSeconds())
            dt = tmp
        }
        return st <= end ? st <= dt && dt <= end : st <= dt || dt <= end
    }
    return false
}

function timeRange() {
    let n = arguments.length
    if (n !== 0) {
        let isGMT = arguments[n - 1] === "GMT"
        if (isGMT && --n === 0) return false
        let dt = new Date()
        let st = new Date()
        let end = new Date()
        let hour = isGMT ? dt.getUTCHours() : dt.getHours()
        switch (n) {
            case 1:
                return hour === arguments[0]
            case 2:
                return arguments[0] <= hour && hour <= arguments[1]
            case 6:
                st.setHours(arguments[0])
                st.setMinutes(arguments[1])
                st.setSeconds(arguments[2])
                end.setHours(arguments[3])
                end.setMinutes(arguments[4])
                end.setSeconds(arguments[5])
                break
            case 4:
                st.setHours(arguments[0])
                st.setMinutes(arguments[1])
                end.setHours(arguments[2])
                end.setMinutes(arguments[3])
                end.setSeconds(59)
                break
            default:
                throw new Error("timeRange: bad number of arguments")
        }
        // noinspection DuplicatedCode
        if (isGMT) {
            let tmp = dt
            tmp.setFullYear(dt.getUTCFullYear())
            tmp.setMonth(dt.getUTCMonth())
            tmp.setDate(dt.getUTCDate())
            tmp.setHours(dt.getUTCHours())
            tmp.setMinutes(dt.getUTCMinutes())
            tmp.setSeconds(dt.getUTCSeconds())
            dt = tmp
        }
        return st <= end ? st <= dt && dt <= end : st <= dt || dt <= end
    }
    return false
}

/* PAC contents */
