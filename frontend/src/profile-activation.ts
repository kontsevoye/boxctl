import { request } from './api'

export function profileActivationPayload() {
  return { confirmRestart: true }
}

export async function activateProfile(profileID: string): Promise<void> {
  await request(`/profiles/${encodeURIComponent(profileID)}/activate`, {
    method: 'POST',
    body: JSON.stringify(profileActivationPayload()),
  })
}
