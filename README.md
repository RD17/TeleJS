# TeleJS - Telegram API implementation for JS

🚩 TeleJS is a pure JavaScript implementation of Telegram MTP protocol

🌟 If you ❤️ library, please star it! 🌟

## Installing

`yarn add telejs`

## Initializing MtpProxy

The main MTP wrapper class is `MtpProxy`, since you do not want to login into Telegram each time you run your app, you should implement two fucntions for saving and restoring the state of `MtpProxy` and pass them to `MtpProxy.init` method:

```
import fs from 'fs'
import { MtpProxy } from 'telejs'

MtpProxy.init(
  (state) => new Promise((resolve, reject) => {
    fs.writeFile('state.json', state, 'utf8', (err) => {
      if (err) {
        reject(err)
        return
      }
      resolve()
    })
  }),
  () => new Promise((resolve, reject) => {
    fs.readFile('state.json', 'utf8', (err, data) => {
      if (err) {
        reject(err)
        return
      }
      resolve(data)
    })
  })
  , 'verbose')
```

After `MtpProxy.init` is called, your `MtpProxy` is ready to work.

## Signing in

```
 MtpProxy.signInUser('YOUR PHONE NUMBER HERE', codeInputPromise)
    .then(res => console.log(res))
    .catch((err) => console.error(err))
```

`codeInputPromise` - Promise that should return the auth code received from Telegram

## Calling Telegram API methods

Please refer to [official Telegram API methods list](https://core.telegram.org/methods) to find available methods.

Here is an example of calling `messages.sendMessage` method:

```
MtpProxy.mtpInvokeApi('messages.sendMessage',
        {
            "random_id": Math.floor(Math.random() * 5000),
            "peer": { "_": "inputPeerUser", "user_id": 'USER ID TO SEND MESSAGE TO', "access_hash": "ACCESS HASH" },
            "message": `How are you doing?`
        }
    )
    .then(res => console.log('sent'))
    .catch(err => console.error(err))
```
