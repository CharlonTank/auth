module Auth.Method.OAuthAuth0 exposing (..)

import Auth.Common exposing (..)
import Auth.HttpHelpers as HttpHelpers
import Auth.Protocol.OAuth
import Base64.Encode as Base64
import Bytes exposing (Bytes)
import Bytes.Encode as Bytes
import Http
import JWT exposing (..)
import JWT.JWS as JWS
import Json.Decode as Json
import OAuth.AuthorizationCode as OAuth
import SeqDict as Dict exposing (SeqDict)
import Task exposing (Task)
import Url exposing (Protocol(..), Url)


configuration :
    String
    -> String
    -> String
    ->
        Method
            frontendMsg
            backendMsg
            { frontendModel | authFlow : Flow, authRedirectBaseUrl : Url }
            backendModel
configuration clientId clientSecret appTenant =
    ProtocolOAuth
        { id = "OAuthAuth0"
        , authorizationEndpoint = { defaultHttpsUrl | host = appTenant, path = "/authorize" }
        , tokenEndpoint = { defaultHttpsUrl | host = appTenant, path = "/oauth/token" }
        , logoutEndpoint =
            Tenant
                { url =
                    { defaultHttpsUrl
                        | host = appTenant
                        , path = "/v2/logout"
                        , query = Just ("client_id=" ++ clientId ++ "&returnTo=")
                    }
                , returnPath = "/logout/OAuthAuth0/callback"
                }
        , allowLoginQueryParameters = True
        , clientId = clientId
        , clientSecret = clientSecret
        , scope = [ "openid email profile" ]
        , getUserInfo = getUserInfo
        , onFrontendCallbackInit = Auth.Protocol.OAuth.onFrontendCallbackInit
        , placeholder = \x -> ()

        -- , onAuthCallbackReceived = Debug.todo "onAuthCallbackReceived"
        }


getUserInfo :
    OAuth.AuthenticationSuccess
    -> Task Auth.Common.Error UserInfo
getUserInfo authenticationSuccess =
    let
        extract : String -> Json.Decoder a -> SeqDict String Json.Value -> Result String a
        extract k d v =
            Dict.get k v
                |> Maybe.map
                    (\value ->
                        case Json.decodeValue d value of
                            Ok decoded ->
                                Ok decoded

                            Err err ->
                                Err <| Json.errorToString err
                    )
                |> Maybe.withDefault (Err <| "Key " ++ k ++ " not found")

        extractOptional : a -> String -> Json.Decoder a -> SeqDict String Json.Value -> Result String a
        extractOptional default k d v =
            Dict.get k v
                |> Maybe.map
                    (\value ->
                        case Json.decodeValue d value of
                            Ok decoded ->
                                Ok decoded

                            Err _ ->
                                Ok default
                    )
                |> Maybe.withDefault (Ok default)

        tokenR =
            case authenticationSuccess.idJwt of
                Nothing ->
                    Err "Identity JWT missing in authentication response. Please report this issue."

                Just idJwt ->
                    case JWT.fromString idJwt of
                        Ok (JWS t) ->
                            Ok t

                        Err err ->
                            Err <| jwtErrorToString err

        stuff =
            tokenR
                |> Result.andThen
                    (\token ->
                        let
                            meta =
                                token.claims.metadata
                        in
                        Result.map4
                            (\email email_verified given_name family_name ->
                                { email = email
                                , email_verified = email_verified
                                , given_name = given_name
                                , family_name = family_name
                                }
                            )
                            (extract "email" Json.string meta)
                            (extract "email_verified" Json.bool meta)
                            (extractOptional Nothing "given_name" (Json.string |> Json.nullable) meta)
                            (extractOptional Nothing "family_name" (Json.string |> Json.nullable) meta)
                    )
    in
    Task.mapError (Auth.Common.ErrAuthString << HttpHelpers.httpErrorToString) <|
        case stuff of
            Ok result ->
                Task.succeed
                    { email = result.email
                    , name =
                        [ Maybe.withDefault "" result.given_name, Maybe.withDefault "" result.family_name ]
                            |> String.join " "
                            |> nothingIfEmpty
                    , username = Nothing
                    }

            Err err ->
                Task.fail (Http.BadBody err)


jwtErrorToString err =
    case err of
        TokenTypeUnknown ->
            "Unsupported auth token type."

        JWSError decodeError ->
            case decodeError of
                JWS.Base64DecodeError ->
                    "Base64DecodeError"

                JWS.MalformedSignature ->
                    "MalformedSignature"

                JWS.InvalidHeader jsonError ->
                    "InvalidHeader: " ++ Json.errorToString jsonError

                JWS.InvalidClaims jsonError ->
                    "InvalidClaims: " ++ Json.errorToString jsonError
