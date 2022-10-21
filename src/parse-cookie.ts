const ATTRS = new Set(["domain", "path", "max-age", "expires", "samesite", "secure", "httponly"])

export interface Attributes {
  maxage?: number
  expires?: Date
  samesite?: "Lax" | "Strict" | "None"
  secure?: boolean
  httponly?: boolean
  domain?: string
  path?: string
}

type Cookie = Attributes & Record<string, string>
export function parseCookie(cookie: string): Cookie {
  let out: Cookie = {},
    idx: number,
    tmp: string
  let i = 0,
    arr = cookie.split(/;\s*/g)
  let key: string, val: string

  for (; i < arr.length; i++) {
    tmp = arr[i]
    idx = tmp.indexOf("=")

    if (!!~idx) {
      key = tmp.substring(0, idx++).trim()
      val = tmp.substring(idx).trim()
      if (val[0] === '"') {
        val = val.substring(1, val.length - 1)
      }
      if (!!~val.indexOf("%")) {
        try {
          val = decodeURIComponent(val)
        } catch (err) {
          /* ignore */
        }
      }
      if (ATTRS.has((tmp = key.toLowerCase()))) {
        if (tmp === "expires") out.expires = new Date(val)
        else if (tmp === "max-age") out.maxage = +val
        else out[tmp] = val
      } else {
        out[key] = val
      }
    } else if ((key = tmp.trim().toLowerCase())) {
      if (key === "httponly" || key === "secure") {
        out[key] = true
      }
    }
  }

  return out
}
