import fs from 'fs'
import chai from 'chai'
import assert from 'assert'
import { MtpDcConfigurator, MtpRsaKeysManager, MtpTimeManager, MtpAuthorizer, MtpProxy } from '../src/Mtp/index'
import readline from 'readline'

const expect = chai.expect

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
  , 'info')

describe('DH test', function () {
  this.timeout(20000)
  this.slow(10000)

  it('should initialize DH params', (done) => {
    MtpAuthorizer.auth(2)
      .then((res) => done())
      .catch((err) => done(err))
  })
})

describe('Test MtpNetworker', function () {
  this.timeout(20000)
  this.slow(10000)

  it('Should return MtpNetworker', (done) => {
    MtpProxy.mtpGetNetworker(2)
      .then((res) => done())
      .catch((err) => done(new Error(err)))
  })
})

describe('Test MtpProxy', function () {
  this.timeout(0)
  this.slow(10000)

  it('Should return dc config', (done) => {
    MtpProxy.mtpInvokeApi("help.getConfig", {})
      .then((res) => {
        expect(res.dc_options).to.be.a('array')
        done()
      })
      .catch((err) => done(new Error(err)))
  })

  it('Should sign in user', (done) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    })

    const codeInputPromise = () => new Promise((resolve, reject) => {
      rl.question('Code? ', (code) => {
        resolve(code)
        rl.close()
      })
    })

    MtpProxy.signInUser('YOUR PHONE NUMBER HERE', codeInputPromise)
      .then(res => {
        done()
      })
      .catch((err) => done(new Error(err)))
  })

  it('should send test message', (done) => {
    const sendMsg = () => {
      console.log('sending')
      MtpProxy.mtpInvokeApi('messages.sendMessage',
        {
          "random_id": Math.floor(Math.random() * 5000),
          "peer": { "_": "inputPeerUser", "user_id": 'USER ID TO SEND MESSAGE TO', "access_hash": "ACCESS HASH" },
          "message": `How are you doing? ${new Date().getMinutes()}`
        }
      )
        .then(res => { console.log('sent') })
        .catch(err => done(new Error(err)))
    }

    sendMsg()
    setInterval(() => sendMsg(), 5 * 60 * 1000)
  })
})