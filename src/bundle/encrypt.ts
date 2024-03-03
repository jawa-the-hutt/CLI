import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'
import { program } from 'commander'
import ciDetect from 'ci-info'
import * as p from '@clack/prompts'
import { checkLatest } from '../api/update'
import { encryptSource } from '../api/crypto'
import { baseKey, baseKeyPub, getLocalConfig, getConfig, keyType, PUBLIC_KEY_TYPE, PRIVATE_KEY_TYPE } from '../utils'

interface Options {
  key?: string
  keyData?: string
}

export async function encryptZip(zipPath: string, options: Options) {
  p.intro(`Encryption`)

  await checkLatest()
  const localConfig = await getLocalConfig()
  const config = await getConfig()
  // console.log('localConfig - ', localConfig)
  // console.log('config - ', config)

  let decryptStrategy;
  let decryptStrategyType: keyType = PRIVATE_KEY_TYPE;
  const hasPrivateKeyInConfig = config?.app?.extConfig?.plugins?.CapacitorUpdater?.privateKey ? true : false
  // console.log(`There ${hasPrivateKeyInConfig ? 'IS' : 'IS NOT'} a privateKey in the config`);

  const hasDecryptStrategyInConfig = config?.app?.extConfig?.plugins?.CapacitorUpdater?.decryptStrategy?.type && config?.app?.extConfig?.plugins?.CapacitorUpdater?.decryptStrategy?.key ? true : false
  // console.log(`There ${hasDecryptStrategyInConfig ? 'IS' : 'IS NOT'} a decryptStrategy in the config`);
  if (!hasPrivateKeyInConfig && hasDecryptStrategyInConfig) {
    decryptStrategy = config.app.extConfig.plugins.CapacitorUpdater.decryptStrategy;
    if (decryptStrategy) decryptStrategyType = decryptStrategy.type;
  }
  // console.log('decryptStrategyType - ', decryptStrategyType);
  p.log.message(`Decrypt Type - ${decryptStrategyType}`)

  // write in file .capgo the apikey in home directory

  if (!existsSync(zipPath)) {
    p.log.error(`Error: Zip not found at the path ${zipPath}`)
    program.error('')
  }

  if (!hasPrivateKeyInConfig && !hasDecryptStrategyInConfig) {
    p.log.error(`Error: Missing Encryption Keys in config`)
    program.error('')
  }

  const keyPath = options.key || hasPrivateKeyInConfig ? baseKeyPub : decryptStrategyType === PRIVATE_KEY_TYPE ? baseKeyPub : baseKey
  // check if publicKey exist

  //let publicKey = options.keyData || ''
  let key = options.keyData || ''

  if (!existsSync(keyPath) && !key) {
    p.log.warning(`Cannot find ${decryptStrategyType === PRIVATE_KEY_TYPE ? PUBLIC_KEY_TYPE : PRIVATE_KEY_TYPE} key ${keyPath} or as keyData option`)
    if (ciDetect.isCI) {
      p.log.error(`Error: Missing ${decryptStrategyType === PRIVATE_KEY_TYPE ? PUBLIC_KEY_TYPE : PRIVATE_KEY_TYPE} key`)
      program.error('')
    }
    const res = await p.confirm({ message: `Do you want to use our ${decryptStrategyType === PRIVATE_KEY_TYPE ? PUBLIC_KEY_TYPE : PRIVATE_KEY_TYPE} key ?` })
    if (!res) {
      p.log.error(`Error: Missing ${decryptStrategyType === PRIVATE_KEY_TYPE ? PUBLIC_KEY_TYPE : PRIVATE_KEY_TYPE} key`)
      program.error('')
    }
    //TODO: based on the other changes and which decrypt strategy they choose, we probably need to determine which signKey is being passed back here?
    key = localConfig.signKey || ''
  }
  else if (existsSync(keyPath)) {
    // open with fs key path
    const keyFile = readFileSync(keyPath)
    key = keyFile.toString()
  }

  // let's doublecheck and make sure the key we are using is the right type based on the decryption strategy
  if (key) {
    if (decryptStrategyType === PRIVATE_KEY_TYPE && !key.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
      p.log.error(`The decryption strategy is: 'private' and the encryption key provided is not a public key`)
      program.error('')
    } 
    if (decryptStrategyType !== PRIVATE_KEY_TYPE && !key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
      p.log.error(`The decryption strategy is: 'public' and the encryption key provided is not a private key`)
      program.error('')
    }
  }

  const zipFile = readFileSync(zipPath)
  const encodedZip = encryptSource(zipFile, key, decryptStrategyType)
  p.log.success(`ivSessionKey: ${encodedZip.ivSessionKey}`)
  // write decodedZip in a file
  writeFileSync(`${zipPath}_encrypted.zip`, encodedZip.encryptedData)
  p.log.success(`Encrypted zip saved at ${zipPath}_encrypted.zip`)
  p.outro(`Done ✅`)
  process.exit()
}
