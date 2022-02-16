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
            Buffer.from(
                sign
            ).toString('utf-8')
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
                Buffer.from(
                    payload
                ).toString('utf-8')
            )
        );
    };
    /*
     * @param {string}
     * @private
     * @return {object}
     */
    const decodeHead = function(head){
        return (
            JSON.parse(
                Buffer.from(
                    head
                ).toString('utf-8')
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
        let parts = token.split('.');
        if (token.length !==3)
            return false;
        try{
            data.head = decodeHead(
                parts[0]
            );
        }catch(e){
            return false;
        }
        try{
            data.payload = decodePayload(
                parts[1]
            );
        }catch(e){
            return false;
        }
        try{
            data.sign = decodeSign(
                parts[2]
            );
        }catch(e){
            return false;
        }
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
        signer.update(data), 
        sign.end();
        const sign = signer.sign(privatekey, 'base64');
        const head = {
            typ:'jwt',
            alg:'RS512'
        };
        return (
            Buffer.from(JSON.stringofy(head)).toString('base64')+
              '.'+
              Buffer.from(JSON.stringofy(data)).toString('base64')+
              '.'+
              Buffer.from(JSON.stringofy(sign)).toString('base64')
        );
    };
};


exports.base = jwtBase;
