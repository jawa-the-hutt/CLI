import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'
import { program } from 'commander'
import * as p from '@clack/prompts'
import { decryptSource } from '../api/crypto'
import { baseKey, baseKeyPub, getConfig, keyType, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE } from '../utils'
import { checkLatest } from '../api/update'

interface Options {
  key?: string
  keyData?: string
}

export async function decryptZip(zipPath: string, ivsessionKey: string, options: Options) {
  p.intro(`Decrypt zip file`)
  await checkLatest()
  // write in file .capgo the apikey in home directory

  if (!existsSync(zipPath)) {
    p.log.error(`Zip not found at the path ${zipPath}`)
    program.error('')
  }

  const config = await getConfig()
  const { extConfig } = config.app
  // console.log('config - ', config)
  // console.log('extConfig - ', extConfig)

  let decryptStrategy;
  let decryptStrategyType: keyType = PRIVATE_KEY_TYPE;
  const hasPrivateKeyInConfig = extConfig?.plugins?.CapacitorUpdater?.privateKey ? true : false
  // console.log(`There ${hasPrivateKeyInConfig ? 'IS' : 'IS NOT'} a privateKey in the config`);

  const hasDecryptStrategyInConfig = extConfig?.plugins?.CapacitorUpdater?.decryptStrategy?.type && extConfig?.plugins?.CapacitorUpdater?.decryptStrategy?.key ? true : false
  // console.log(`There ${hasDecryptStrategyInConfig ? 'IS' : 'IS NOT'} a decryptStrategy in the config`);
  if (!hasPrivateKeyInConfig && hasDecryptStrategyInConfig) {
    decryptStrategy = config.app.extConfig.plugins.CapacitorUpdater.decryptStrategy;
    if (decryptStrategy) decryptStrategyType = decryptStrategy.type;
  }
  // console.log('decryptStrategyType - ', decryptStrategyType);
  p.log.message(`Decrypt Type - ${decryptStrategyType}`)

  if (!hasPrivateKeyInConfig && !hasDecryptStrategyInConfig) {
    p.log.error(`Error: Missing Encryption Keys in config`)
    program.error('')
  }

  if (!options.key && !existsSync(decryptStrategyType === PRIVATE_KEY_TYPE ? baseKey : baseKeyPub)) {
    p.log.error(`Key not found at the path ${decryptStrategyType === PRIVATE_KEY_TYPE ? baseKey : baseKeyPub} or in ${config.app.extConfigFilePath}`)
    program.error('')
  }
  const keyPath = options.key || hasPrivateKeyInConfig ? baseKey : decryptStrategyType === PRIVATE_KEY_TYPE ? baseKey : baseKeyPub
  // check if private exist

  let key = hasPrivateKeyInConfig ? extConfig?.plugins?.CapacitorUpdater?.privateKey : hasDecryptStrategyInConfig ? extConfig?.plugins?.CapacitorUpdater?.decryptStrategy?.key : ''

  if (!existsSync(keyPath) && !key) {
    p.log.error(`Cannot find ${decryptStrategyType === PRIVATE_KEY_TYPE ? PRIVATE_KEY_TYPE : PUBLIC_KEY_TYPE} key ${keyPath} or as keyData option or in ${config.app.extConfigFilePath}`)
    program.error('')
  }
  else if (existsSync(keyPath)) {
    // open with fs publicKey path
    const keyFile = readFileSync(keyPath)
    key = keyFile.toString()
  }

  // let's doublecheck and make sure the key we are using is the right type based on the decryption strategy
  if (key) {
    if (decryptStrategyType === PRIVATE_KEY_TYPE && !key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
      p.log.error(`The decryption strategy is: 'private' and the decryption key provided is not a private key`)
      program.error('')
    } 
    if (decryptStrategyType !== PRIVATE_KEY_TYPE && !key.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
      p.log.error(`The decryption strategy is: 'public' and the decryption key provided is not a public key`)
      program.error('')
    }
  }

  const zipFile = readFileSync(zipPath)

  const decodedZip = decryptSource(zipFile, ivsessionKey, options.keyData ?? key ?? '',  decryptStrategyType === PRIVATE_KEY_TYPE ? PRIVATE_KEY_TYPE : PUBLIC_KEY_TYPE)
  // write decodedZip in a file
  writeFileSync(`${zipPath}_decrypted.zip`, decodedZip)
  p.log.success(`Decrypted zip file at ${zipPath}_decrypted.zip`)
  p.outro(`Done ✅`)
  process.exit()
}
