/*
 *  @Soldy\jwtrc\2021.02.16\GPL3
 */
'use strict';
const crypto = require('crypto');
/*
 * @param {integer} limitIn //maximum size of package
 * @prototype
 */
const jwtBase = function(){
    /*
     * @param {string}
     * @param {string}
     * @public
     * @return {object}
     */
    this.decode = function(token, publickey){
        return decode(token, publickey);
    };
    /*
     * @param {object}
     * @param {string}
     * @public
     * @return {string} 
     */
    this.encode = function(data, privatekey){
        return encode(data, privatekey);
    };
    /*
     * @param {string}
     * @private
     * @return Buffer
     */
    const decodeSign = function(sign){
        return (
            Buffer.from(sign, 'base64').toString('utf-8')
        );
    };
    /*
     * @param {string}
     * @private
     * @return {buffer}
     */
    const decodePayload = function(payload){
        return (
            JSON.parse(
                Buffer.from(payload, 'base64').toString('utf8')
            )
        );
    };
    /*
     * @param {string}
     * @private
     * @return {object}
     */
    const _decodeHead = function(head){
        return (
            JSON.parse(
                Buffer.from(head, 'base64').toString('utf8')
            )
        );
    };
    /*
     * @param {string}
     * @param {string}
     * @private
     * @return {object}
     */
    const decode = function(token, publickey){
        let data = {};
        let parts = token.toString('utf8').split('.');
        if (parts.length !==3)
            throw Error ('Wrong token size : ' + parts.length.toString());
        try{
            data.head = _decodeHead(
                parts[0]
            );
        }catch(e){
            throw Error (e);
        }
        try{
            data.payload = decodePayload(
                parts[1]
            );
        }catch(e){
            throw Error (e);
        }
        try{
            data.sign = decodeSign(
                parts[2]
            );
        }catch(e){
            throw Error (e);
        }
        console.log(parts[2]);
        console.log(parts[2]);
        console.log(parts[2]);
        console.log(parts[2]);
        console.log(parts[2]);
        console.log(parts[2]);
        const verify  =  crypto.createVerify('RSA-SHA512');
        console.log(verify.verify(
            publickey,
            parts[1],
            Buffer.from(data.sign)
        ));
        console.log(JSON.stringify(data.payload));
        return data;
    };
    /*
     * @param {object}
     * @param {string}
     * @private
     * @return {string} 
     */
    const encode = function(data, privatekey){
        let signer = crypto.createSign('RSA-SHA512');
        signer.update(Buffer.from(JSON.stringify(data)).toString('base64'));
        signer.end();
        const sign = signer.sign(privatekey, 'base64');
        const head = {
            typ:'jwt',
            alg:'RS512'
        };
        return (
            Buffer.from(JSON.stringify(head)).toString('base64')+
              '.'+
              Buffer.from(JSON.stringify(data)).toString('base64')+
              '.'+
              sign
        );
    };
};


exports.base = jwtBase;
