import { APIError, request, setCSRFToken } from './api'
import type { Session } from './types'

export interface Passkey {
  id: string
  name: string
  rpId: string
  createdAt: string
  lastUsedAt?: string
}

export interface PasskeySettings {
  passkeys: Passkey[]
  registrationAvailable: boolean
  rpId: string
  limit: number
}

type DescriptorJSON = Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }
export type CreationOptionsJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string
  user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }
  excludeCredentials?: DescriptorJSON[]
}
export type RequestOptionsJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string
  allowCredentials?: DescriptorJSON[]
}
interface Ceremony<T> { ceremonyId: string; options: { publicKey: T } }

export function passkeySupport(): 'available' | 'insecure' | 'unsupported' {
  if (typeof window === 'undefined') return 'unsupported'
  const host = window.location.hostname
  if (!window.isSecureContext || (window.location.protocol !== 'https:' && host !== 'localhost') || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return 'insecure'
  return typeof PublicKeyCredential !== 'undefined' && typeof navigator.credentials?.create === 'function' && typeof navigator.credentials?.get === 'function' ? 'available' : 'unsupported'
}

export function decodeBase64URL(value: string): ArrayBuffer {
  const decoded = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0)).buffer
}

export function encodeBase64URL(value: ArrayBuffer): string {
  return btoa(Array.from(new Uint8Array(value), (byte) => String.fromCharCode(byte)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function creationOptions(options: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  return { ...options, challenge: decodeBase64URL(options.challenge), user: { ...options.user, id: decodeBase64URL(options.user.id) }, excludeCredentials: options.excludeCredentials?.map((credential) => ({ ...credential, id: decodeBase64URL(credential.id) })) }
}

export function requestOptions(options: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  return { ...options, challenge: decodeBase64URL(options.challenge), allowCredentials: options.allowCredentials?.map((credential) => ({ ...credential, id: decodeBase64URL(credential.id) })) }
}

// Explicit serialization also supports browsers without credential.toJSON().
export function credentialJSON(credential: PublicKeyCredential) {
  const response = credential.response
  const shared = { id: credential.id, rawId: encodeBase64URL(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults() }
  if ('attestationObject' in response) {
    const registration = response as AuthenticatorAttestationResponse
    return { ...shared, response: { clientDataJSON: encodeBase64URL(response.clientDataJSON), attestationObject: encodeBase64URL(registration.attestationObject), transports: registration.getTransports?.() ?? [] } }
  }
  const assertion = response as AuthenticatorAssertionResponse
  return { ...shared, response: { clientDataJSON: encodeBase64URL(response.clientDataJSON), authenticatorData: encodeBase64URL(assertion.authenticatorData), signature: encodeBase64URL(assertion.signature), userHandle: assertion.userHandle ? encodeBase64URL(assertion.userHandle) : null } }
}

export async function registerPasskey(name: string, password: string, signal?: AbortSignal): Promise<Passkey[]> {
  const ceremony = await request<Ceremony<CreationOptionsJSON>>('/settings/passkeys/register/begin', { method: 'POST', body: JSON.stringify({ name: name.trim(), password }), signal })
  const credential = await navigator.credentials.create({ publicKey: creationOptions(ceremony.options.publicKey), signal }) as PublicKeyCredential | null
  if (!credential) throw new DOMException('No passkey was created', 'NotAllowedError')
  return request<Passkey[]>('/settings/passkeys/register/finish', { method: 'POST', body: JSON.stringify({ ceremonyId: ceremony.ceremonyId, credential: credentialJSON(credential) }), signal })
}

export async function loginWithPasskey(signal?: AbortSignal): Promise<Session> {
  const ceremony = await request<Ceremony<RequestOptionsJSON>>('/auth/passkeys/begin', { method: 'POST', body: '{}', signal })
  const credential = await navigator.credentials.get({ publicKey: requestOptions(ceremony.options.publicKey), signal }) as PublicKeyCredential | null
  if (!credential) throw new DOMException('No passkey was selected', 'NotAllowedError')
  const session = await request<Session>('/auth/passkeys/finish', { method: 'POST', body: JSON.stringify({ ceremonyId: ceremony.ceremonyId, credential: credentialJSON(credential) }), signal })
  setCSRFToken(session.csrfToken)
  return session
}

export async function deletePasskey(id: string, password: string): Promise<void> {
  await request('/settings/passkeys', { method: 'DELETE', body: JSON.stringify({ id, password }) })
}

export function passkeyError(reason: unknown, t: (key: string) => string): string {
  if (reason instanceof DOMException) {
    if (reason.name === 'NotAllowedError' || reason.name === 'AbortError') return t('passkeyCanceled')
    if (reason.name === 'InvalidStateError') return t('passkeyExists')
    if (reason.name === 'SecurityError') return t('passkeySecureContext')
    if (reason.name === 'NotSupportedError') return t('passkeyUnsupported')
  }
  if (reason instanceof APIError) {
    const key: Record<string, string> = { invalid_password: 'passkeyInvalidPassword', passkey_origin_unavailable: 'passkeySecureContext', passkey_verification_failed: 'passkeyVerificationFailed', passkey_exists: 'passkeyExists', passkey_limit: 'passkeyLimit', invalid_passkey_name: 'passkeyInvalidName', rate_limited: 'passkeyRateLimited' }
    return key[reason.code] ? t(key[reason.code]!) : reason.message
  }
  return t('passkeyRequestFailed')
}
