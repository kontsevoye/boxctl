import { describe, expect, it } from 'vitest'
import { subscriptionRequestHeaders } from './ProxySubscriptionsPage'

describe('subscriptionRequestHeaders', () => {
  it('keeps only non-empty safe device headers and trims their values', () => {
    expect(subscriptionRequestHeaders({
      userAgent: ' boxctl-test ',
      hwid: 'device-id',
      deviceOS: ' OpenWrt ',
      versionOS: '',
      deviceModel: ' Example Router ',
    })).toEqual({
      'User-Agent': 'boxctl-test',
      'X-HWID': 'device-id',
      'X-Device-OS': 'OpenWrt',
      'X-Device-Model': 'Example Router',
    })
  })
})
