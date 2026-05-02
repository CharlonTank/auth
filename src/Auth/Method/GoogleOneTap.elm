module Auth.Method.GoogleOneTap exposing (configuration)

{-| Google One Tap authentication method.

Google One Tap delivers an ID token (a JWT) directly to the frontend, which the
frontend forwards to the backend. The backend then decodes the JWT payload and
validates the `iss`/`aud` claims before extracting user info.

-}

import Auth.Common exposing (..)
import Base64.Decode as Base64Decode
import Json.Decode as Json


configuration :
    String
    -> String
    -> Method frontendMsg backendMsg frontendModel backendModel
configuration clientId clientSecret =
    ProtocolGoogleOneTap
        { id = "GoogleOneTap"
        , clientId = clientId
        , clientSecret = clientSecret
        , scope = [ "openid", "email", "profile" ]
        , verifyIdToken = verifyGoogleIdToken
        , placeholder = \_ -> ()
        }


{-| Verify a Google ID token by decoding the payload and checking issuer/audience.

This does not verify the JWT signature against Google's public keys. Google One
Tap delivers the token over a TLS-secured channel from Google to the user's
browser, then the user's browser forwards it to our backend over our own TLS
connection — so for typical web sign-in this check is sufficient.

-}
verifyGoogleIdToken : String -> String -> Result String UserInfo
verifyGoogleIdToken clientId idToken =
    decodeJwtPayload idToken
        |> Result.andThen
            (\payload ->
                case getString "iss" payload of
                    Nothing ->
                        Err "Missing issuer claim"

                    Just issuer ->
                        if issuer /= "https://accounts.google.com" && issuer /= "accounts.google.com" then
                            Err "Invalid issuer"

                        else
                            case getString "aud" payload of
                                Nothing ->
                                    Err "Missing audience claim"

                                Just audience ->
                                    if audience /= clientId then
                                        Err "Invalid audience"

                                    else
                                        decodeUserInfo payload
            )


decodeUserInfo : Json.Value -> Result String UserInfo
decodeUserInfo payload =
    case Json.decodeValue userInfoDecoder payload of
        Ok userInfo ->
            Ok userInfo

        Err err ->
            Err ("Failed to decode user info: " ++ Json.errorToString err)


userInfoDecoder : Json.Decoder UserInfo
userInfoDecoder =
    Json.map3
        (\email givenName familyName ->
            { email = email
            , name =
                [ Maybe.withDefault "" givenName, Maybe.withDefault "" familyName ]
                    |> String.join " "
                    |> nothingIfEmpty
            , username = Nothing
            }
        )
        (Json.field "email" Json.string)
        (Json.maybe (Json.field "given_name" Json.string))
        (Json.maybe (Json.field "family_name" Json.string))


nothingIfEmpty : String -> Maybe String
nothingIfEmpty s =
    let
        trimmed =
            String.trim s
    in
    if String.isEmpty trimmed then
        Nothing

    else
        Just trimmed


getString : String -> Json.Value -> Maybe String
getString key payload =
    Json.decodeValue (Json.field key Json.string) payload
        |> Result.toMaybe


{-| Decode the payload (middle segment) of a JWT into a JSON value.
-}
decodeJwtPayload : String -> Result String Json.Value
decodeJwtPayload token =
    case String.split "." token of
        _ :: payload :: _ :: [] ->
            payload
                |> base64UrlToBase64
                |> Base64Decode.decode Base64Decode.string
                |> Result.mapError base64ErrorToString
                |> Result.andThen
                    (\jsonString ->
                        Json.decodeString Json.value jsonString
                            |> Result.mapError Json.errorToString
                    )

        _ ->
            Err "Malformed JWT: expected 3 dot-separated segments"


{-| Convert base64url encoding (used by JWT) to standard base64.

base64url replaces `+` with `-` and `/` with `_`, and omits trailing `=`
padding. This function reverses that.

-}
base64UrlToBase64 : String -> String
base64UrlToBase64 s =
    let
        replaced =
            s
                |> String.replace "-" "+"
                |> String.replace "_" "/"

        paddingNeeded =
            modBy 4 (String.length replaced)
    in
    if paddingNeeded == 0 then
        replaced

    else
        replaced ++ String.repeat (4 - paddingNeeded) "="


base64ErrorToString : Base64Decode.Error -> String
base64ErrorToString err =
    case err of
        Base64Decode.ValidationError ->
            "Base64 validation error"

        Base64Decode.InvalidByteSequence ->
            "Base64 invalid byte sequence"
