import { IConfigComponent, IHttpServerComponent, ILoggerComponent } from "@well-known-components/interfaces"
import jwt_decode, { JwtPayload } from "jwt-decode"
import { base64url } from "rfc4648"
import { parseCookie } from "./parse-cookie"
import { subtle } from "crypto"
import { IFetchComponent } from "@well-known-components/http-server"

/**
 * @public
 */
export type JwtPayloadExtended = JwtPayload & { kid: string; name: string; email: string }

type CloudflareConfig = {
  CF_ACCESS_TEAM_NAME: string
  CF_ACCESS_APP_AUD: string
}

/**
 * @public
 */
export type CloudflareAuthenticatorComponent<Context> = {
  getUserFromContext(ctx: Context): JwtPayloadExtended | undefined
  getMiddleware(): IHttpServerComponent.IRequestHandler<Context>
}

/**
 * @public
 */
export type RequiredComponents = {
  logs: ILoggerComponent
  config: IConfigComponent
  fetch: IFetchComponent
}

/**
 * @public
 */
export async function createCloudflareAuthenticator<Context>(
  components: Pick<RequiredComponents, "logs" | "config" | "fetch">
): Promise<CloudflareAuthenticatorComponent<Context>> {
  const logger = components.logs.getLogger("CloudflareSSO")

  const config: CloudflareConfig | undefined = (await components.config.getString("CF_ACCESS_TEAM_NAME"))
    ? {
        CF_ACCESS_TEAM_NAME: await components.config.requireString("CF_ACCESS_TEAM_NAME"),
        CF_ACCESS_APP_AUD: await components.config.requireString("CF_ACCESS_APP_AUD"),
      }
    : undefined

  if (!config) {
    logger.info("IMPORTANT! running unauthenticated mode. CF_ACCESS_TEAM_NAME not configured")
  }

  const UserSymbol = Symbol("UserSymbol")

  function setUser(ctx: Context, user: JwtPayloadExtended | undefined) {
    ;(ctx as any)[UserSymbol] = user
  }

  return {
    getUserFromContext(ctx: Context): JwtPayloadExtended | undefined {
      return (ctx as any)[UserSymbol]
    },
    getMiddleware(): IHttpServerComponent.IRequestHandler<Context> {
      return async (ctx, next) => {
        if (!config) {
          return next()
        }

        // Validate JWT and pass user info to next middlewares/onRequest handler
        try {
          // Validate Cloudflare Access JWT token and return decoded data
          const decodedJwt = await verifyCloudflareAccessJwt(components, ctx.request, config)
          if (!decodedJwt.success) {
            throw new Error(decodedJwt.error)
          }

          // Pass user info to next handlers
          setUser(ctx, decodedJwt.payload)

          return next()
        } catch (e: any) {
          logger.error(e)
        }

        return { status: 401 }
      }
    },
  }
}

// Verify Cloudflare Access JWT
const verifyCloudflareAccessJwt = async (
  components: Pick<RequiredComponents, "fetch">,
  request: IHttpServerComponent.IRequest,
  config: CloudflareConfig
) => {
  try {
    const cookie = parseCookie(request.headers.get("Cookie") || "")
    const jwtToken = request.headers.get("Cf-Access-Jwt-Assertion") || cookie["CF_Authorization"]

    // Make sure JWT or client id/secret was passed
    if (!jwtToken) {
      throw new Error("Missing Cf-Access-Jwt-Assertion header, make sure this endpoint is behind Cloudflare Access")
    }

    const header = jwt_decode(jwtToken, { header: true }) as JwtPayloadExtended
    const payload = jwt_decode(jwtToken) as JwtPayloadExtended
    const jwk = await getCloudflareAccessJwk(components, header.kid, config)

    const verified = await verifyJwtSignature(jwtToken, jwk)
    if (!verified) throw "JWT token could not be verified"

    if (!payload.aud?.includes(config.CF_ACCESS_APP_AUD)) throw "JWT token 'aud' is not valid"
    if (payload.iss !== `https://${config.CF_ACCESS_TEAM_NAME}.cloudflareaccess.com`)
      throw "JWT token issuer is not valid"

    const currentTime = Math.floor(Date.now() / 1000)
    if (payload.exp! < currentTime) throw "JWT token is expired"
    if (payload.iat! > currentTime) throw "JWT token issued in the future"
    if (payload.nbf! > currentTime) throw "JWT token is not valid yet"

    return {
      success: true,
      header,
      payload,
    }
  } catch (e: any) {
    return {
      success: false,
      error: e.toString(),
    }
  }
}

// Get Cloudflare Access jwk for key id
const getCloudflareAccessJwk = async (
  components: Pick<RequiredComponents, "fetch">,
  kid: string,
  config: CloudflareConfig
) => {
  type JwkKeys = {
    keys: Record<string, string>[]
  }

  // TODO implement caching
  const apiRes = await components.fetch.fetch(
    `https://${config.CF_ACCESS_TEAM_NAME}.cloudflareaccess.com/cdn-cgi/access/certs`
  )
  return ((await apiRes.json()) as JwkKeys).keys.find((x) => x.kid === kid)
}

const verifyJwtSignature = (jwsObject: string, jwk: any) => {
  const jwsSigningInput = jwsObject.split(".").slice(0, 2).join(".")
  const jwsSignature = jwsObject.split(".")[2]
  return subtle
    .importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      false,
      ["verify"]
    )
    .then((key) =>
      subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        key,
        base64url.parse(jwsSignature, { loose: true }),
        new TextEncoder().encode(jwsSigningInput)
      )
    )
}
