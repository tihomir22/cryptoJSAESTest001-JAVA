import { Component } from '@angular/core';
import { Dembow } from './dembow';
import * as CryptoJS from 'crypto-js';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'testCryptoJS';

  constructor() { }

  ngOnInit(): void {



    let iterationCount = 1000;
    let keySize = 128;
    let encryptionKey = "Abcdefghijklmnop";
    let dataToDecrypt = "jUQUOJG15LGYqqZBJbLJlQOLtqajh2k6uWuMLmo+tMURG+2b/xGI0Xm7d6Udt0HJ" //The base64 encoded string output from Java;
    let iv = "dc0da04af8fee58593442bf834b30739"
    let salt = "dc0da04af8fee58593442bf834b30739"

    let aesUtilw = new Dembow(keySize, iterationCount);
    let plaintext = aesUtilw.decrypt(salt, iv, encryptionKey, dataToDecrypt);
    console.log(plaintext)
  }

}
