import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { program } from 'commander'
import { writeConfig } from '@capacitor/cli/dist/config'
import * as p from '@clack/prompts'
import { createRSA } from './api/crypto'
import { baseKey, baseKeyPub, getConfig, keyType, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE } from './utils'
import { checkLatest } from './api/update'

interface saveOptions {
  key?: string
  keyData?: string
}
interface Options {
  force?: boolean
}

export async function saveKey(options: saveOptions, log = true) {
  if (log)
    p.intro(`Save keys 🔑`)

  const config = await getConfig()
  const { extConfig } = config.app

  let decryptStrategy;
  let decryptStrategyType: keyType = PRIVATE_KEY_TYPE;
  const hasDecryptStrategyInConfig = config?.app?.extConfig?.plugins?.CapacitorUpdater?.decryptStrategy?.type ? true : false
  // console.log(`There ${hasDecryptStrategyInConfig ? 'IS' : 'IS NOT'} a decryptStrategy in the config`);
  if (hasDecryptStrategyInConfig) {
    decryptStrategy = config.app.extConfig.plugins.CapacitorUpdater.decryptStrategy;
    if (decryptStrategy) decryptStrategyType = decryptStrategy.type;
  }

  console.log('decryptStrategyType - ', decryptStrategyType);

  //const keyPath = options.key || baseKey
  const keyPath = options.key || decryptStrategyType === PRIVATE_KEY_TYPE ? baseKey : baseKeyPub
  // check if publicKey exist

  let key = options.keyData || ''

  if (!existsSync(keyPath) && !key) {
    if (log) {
      p.log.error(`Cannot find ${decryptStrategyType === PRIVATE_KEY_TYPE ? PRIVATE_KEY_TYPE : PUBLIC_KEY_TYPE} key ${keyPath} or as keyData option or in ${config.app.extConfigFilePath}`)
      program.error('')
    }
    else {
      return false
    }
  }
  else if (existsSync(keyPath)) {
    // open with fs publicKey path
    const keyFile = readFileSync(keyPath)
    key = keyFile.toString()
  }

  // let's doublecheck and make sure the key we are saving is the right type based on the decryption strategy
  if (key) {
    if (decryptStrategyType === PRIVATE_KEY_TYPE && key.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
      if (log) {
        p.log.error(`The decryption strategy is: ${decryptStrategyType} and the key is a public key`)
        program.error('')
      } else {
        return false;
      }
    } 
    if (decryptStrategyType !== PRIVATE_KEY_TYPE && key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
      if (log) {
        p.log.error(`The decryption strategy is: ${decryptStrategyType} and the key is a private key`)
        program.error('')
      } else {
        return false;
      }
    }
  }

  if (extConfig) {
    if (!extConfig.plugins) {
      extConfig.plugins = {
        extConfig: {},
        CapacitorUpdater: {
          decryptStrategy: {
            type: PRIVATE_KEY_TYPE
          }
        },
      }
    }
    if (!extConfig.plugins.CapacitorUpdater)
      extConfig.plugins.CapacitorUpdater = {
        decryptStrategy: {
          type: PRIVATE_KEY_TYPE
        }
      }

    if (!extConfig.plugins.CapacitorUpdater.decryptStrategy) {
      extConfig.plugins.CapacitorUpdater.decryptStrategy = {
        type: decryptStrategyType
      }
    }
    
    //TODO: this might be a breaking change if user has other code looking at the specific value in the config file
    if (extConfig.plugins.CapacitorUpdater.privateKey) delete extConfig.plugins.CapacitorUpdater.privateKey;
    extConfig.plugins.CapacitorUpdater.decryptStrategy.key = key;

    // console.log('extConfig', extConfig)
    writeConfig(extConfig, config.app.extConfigFilePath)
  }
  if (log) {
    p.log.success(`${decryptStrategyType === PRIVATE_KEY_TYPE ? PUBLIC_KEY_TYPE : PRIVATE_KEY_TYPE} key saved into ${config.app.extConfigFilePath} file in local directory`)
    p.log.success(`your app will decode the zip archive with this key`)
  }
  return true
}
export async function saveKeyCommand(options: saveOptions) {
  p.intro(`Save keys 🔑`)
  await checkLatest()
  await saveKey(options)
}

export async function createKey(options: Options, log = true) {
  // write in file .capgo the apikey in home directory
  if (log)
    p.intro(`Create keys 🔑`)

  const { publicKey, privateKey } = createRSA()

  // check if baseName already exist
  if (existsSync(baseKeyPub) && !options.force) {
    if (log) {
      p.log.error('Public Key already exists, use --force to overwrite')
      program.error('')
    }
    else {
      return false
    }
  }
  writeFileSync(baseKeyPub, publicKey)
  if (existsSync(baseKey) && !options.force) {
    if (log) {
      p.log.error('Private Key already exists, use --force to overwrite')
      program.error('')
    }
    else {
      return false
    }
  }
  writeFileSync(baseKey, privateKey)

  const config = await getConfig()
  const { extConfig } = config.app
  let decryptStrategyType: keyType = PRIVATE_KEY_TYPE;

  if (extConfig) {
    if (!extConfig.plugins) {
      extConfig.plugins = {
        extConfig: {},
        CapacitorUpdater: {
          decryptStrategy: {
            type: decryptStrategyType
          }
        },
      }
    }

    if (!extConfig.plugins.CapacitorUpdater) {
      extConfig.plugins.CapacitorUpdater = {
        decryptStrategy: {
          type: decryptStrategyType
        }
      }
    }

    if (!extConfig.plugins.CapacitorUpdater.decryptStrategy) {
      extConfig.plugins.CapacitorUpdater.decryptStrategy = {
        type: decryptStrategyType
      }
    }
    
    //TODO: this might be a breaking change if user has other code looking at the specific value in the config file
    if (extConfig.plugins.CapacitorUpdater.privateKey) delete extConfig.plugins.CapacitorUpdater.privateKey;

    decryptStrategyType = extConfig.plugins.CapacitorUpdater.decryptStrategy.type;

    if (decryptStrategyType === PRIVATE_KEY_TYPE) {
      extConfig.plugins.CapacitorUpdater.decryptStrategy.key = privateKey;
    } else {
      extConfig.plugins.CapacitorUpdater.decryptStrategy.key = publicKey;
    }

    // console.log('extConfig', extConfig)
    writeConfig(extConfig, config.app.extConfigFilePath)
  }

  if (log) {
    p.log.success('Your RSA key has been generated')
    p.log.success(`Public key saved in ${baseKeyPub}`)
    if (decryptStrategyType === PRIVATE_KEY_TYPE) {
      p.log.success('This key will be use to encrypt your bundle before sending it to Capgo')
      p.log.success('Keep it safe')
      p.log.success('Than make it unreadable by Capgo and unmodifiable by anyone')
    } else {
      p.log.success('Your app will be the only one having it')
      p.log.success('Only your users can decrypt your update')
      p.log.success('Only you can send them an update')
    }
    p.log.success(`Private key saved in ${config.app.extConfigFilePath}`)
    if (decryptStrategyType !== PRIVATE_KEY_TYPE) {
      p.log.success('This key will be use to encrypt your bundle before sending it to Capgo')
      p.log.success('Keep it safe')
      p.log.success('Than make it unreadable by Capgo and unmodifiable by anyone')
    } else {
      p.log.success('Your app will be the only one having it')
      p.log.success('Only your users can decrypt your update')
      p.log.success('Only you can send them an update')
    }
    p.outro(`Done ✅`)
  }
  return true
}

export async function createKeyCommand(options: Options) {
  await checkLatest()
  await createKey(options)
}
