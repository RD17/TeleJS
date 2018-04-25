import Config from '../config.js'
import { getState } from '../state.js'

export function chooseServer(dcId) {
  let dcConfig = getState().dc_options

  // Excluding ipV6
  dcConfig = dcConfig.filter(dc => !dc.pFlags.ipv6)

  const dcOption = dcConfig.find(dc => dc.id == dcId)

  if (!dcOption) {
    throw new Error(`Could not find dc with id = ${dcId}`)
  }

  return `http://${dcOption.ip_address}:${dcOption.port}/${Config.Modes.test ? 'apiw_test1' : 'apiw1'}`
}
