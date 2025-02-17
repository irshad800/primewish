/*! For license information please see toggle-count.js.LICENSE.txt */
!function(t,e){if("object"==typeof exports&&"object"==typeof module)module.exports=e();else if("function"==typeof define&&define.amd)define([],e);else{var n=e();for(var o in n)("object"==typeof exports?exports:t)[o]=n[o]}}(self,(()=>(()=>{"use strict";var t={737:(t,e)=>{Object.defineProperty(e,"__esModule",{value:!0});var n=function(){function t(t,e,n){this.el=t,this.options=e,this.events=n,this.el=t,this.options=e,this.events={}}return t.prototype.isIOS=function(){return!!/iPad|iPhone|iPod/.test(navigator.platform)||navigator.maxTouchPoints&&navigator.maxTouchPoints>2&&/MacIntel/.test(navigator.platform)},t.prototype.isIpadOS=function(){return navigator.maxTouchPoints&&navigator.maxTouchPoints>2&&/MacIntel/.test(navigator.platform)},t.prototype.createCollection=function(t,e){var n;t.push({id:(null===(n=null==e?void 0:e.el)||void 0===n?void 0:n.id)||t.length+1,element:e})},t.prototype.fireEvent=function(t,e){if(void 0===e&&(e=null),this.events.hasOwnProperty(t))return this.events[t](e)},t.prototype.dispatch=function(t,e,n){void 0===n&&(n=null);var o=new CustomEvent(t,{detail:{payload:n},bubbles:!0,cancelable:!0,composed:!1});e.dispatchEvent(o)},t.prototype.on=function(t,e){this.events[t]=e},t.prototype.afterTransition=function(t,e){var n=function(){e(),t.removeEventListener("transitionend",n,!0)};"all 0s ease 0s"!==window.getComputedStyle(t,null).getPropertyValue("transition")?t.addEventListener("transitionend",n,!0):e()},t.prototype.onTransitionEnd=function(t,e){t.addEventListener("transitionend",(function n(o){o.target===t&&(t.removeEventListener("transitionend",n),e())}))},t.prototype.getClassProperty=function(t,e,n){return void 0===n&&(n=""),(window.getComputedStyle(t).getPropertyValue(e)||n).replace(" ","")},t.prototype.getClassPropertyAlt=function(t,e,n){void 0===n&&(n="");var o="";return t.classList.forEach((function(t){t.includes(e)&&(o=t)})),o.match(/:(.*)]/)?o.match(/:(.*)]/)[1]:n},t.prototype.htmlToElement=function(t){var e=document.createElement("template");return t=t.trim(),e.innerHTML=t,e.content.firstChild},t.prototype.classToClassList=function(t,e,n){void 0===n&&(n=" "),t.split(n).forEach((function(t){return e.classList.add(t)}))},t.prototype.debounce=function(t,e){var n,o=this;return void 0===e&&(e=200),function(){for(var i=[],r=0;r<arguments.length;r++)i[r]=arguments[r];clearTimeout(n),n=setTimeout((function(){t.apply(o,i)}),e)}},t.prototype.checkIfFormElement=function(t){return t instanceof HTMLInputElement||t instanceof HTMLTextAreaElement||t instanceof HTMLSelectElement},t.isEnoughSpace=function(t,e,n,o,i){void 0===n&&(n="auto"),void 0===o&&(o=10),void 0===i&&(i=null);var r=e.getBoundingClientRect(),a=i?i.getBoundingClientRect():null,s=window.innerHeight,u=a?r.top-a.top:r.top,l=(i?a.bottom:s)-r.bottom,c=t.clientHeight+o;return"bottom"===n?l>=c:"top"===n?u>=c:u>=c||l>=c},t.isParentOrElementHidden=function(t){return!!t&&("none"===window.getComputedStyle(t).display||this.isParentOrElementHidden(t.parentElement))},t}();e.default=n,window.HSStaticMethods={afterTransition:function(t,e){var n=function(){e(),t.removeEventListener("transitionend",n,!0)};"all 0s ease 0s"!==window.getComputedStyle(t,null).getPropertyValue("transition")?t.addEventListener("transitionend",n,!0):e()},getClassPropertyAlt:function(t,e,n){void 0===n&&(n="");var o="";return t.classList.forEach((function(t){t.includes(e)&&(o=t)})),o.match(/:(.*)]/)?o.match(/:(.*)]/)[1]:n},getClassProperty:function(t,e,n){return void 0===n&&(n=""),(window.getComputedStyle(t).getPropertyValue(e)||n).replace(" ","")}}},87:function(t,e,n){var o,i=this&&this.__extends||(o=function(t,e){return o=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(t,e){t.__proto__=e}||function(t,e){for(var n in e)Object.prototype.hasOwnProperty.call(e,n)&&(t[n]=e[n])},o(t,e)},function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Class extends value "+String(e)+" is not a constructor or null");function n(){this.constructor=t}o(t,e),t.prototype=null===e?Object.create(e):(n.prototype=e.prototype,new n)}),r=this&&this.__assign||function(){return r=Object.assign||function(t){for(var e,n=1,o=arguments.length;n<o;n++)for(var i in e=arguments[n])Object.prototype.hasOwnProperty.call(e,i)&&(t[i]=e[i]);return t},r.apply(this,arguments)};Object.defineProperty(e,"__esModule",{value:!0});var a=function(t){function e(e,n){var o=t.call(this,e,n)||this,i=e.getAttribute("data-hs-toggle-count"),a=i?JSON.parse(i):{},s=r(r({},a),n);return o.target=(null==s?void 0:s.target)?"string"==typeof(null==s?void 0:s.target)?document.querySelector(s.target):s.target:null,o.min=(null==s?void 0:s.min)||0,o.max=(null==s?void 0:s.max)||0,o.duration=(null==s?void 0:s.duration)||700,o.isChecked=o.target.checked||!1,o.target&&o.init(),o}return i(e,t),e.prototype.init=function(){var t=this;this.createCollection(window.$hsToggleCountCollection,this),this.isChecked&&(this.el.innerText=String(this.max)),this.target.addEventListener("change",(function(){t.isChecked=!t.isChecked,t.toggle()}))},e.prototype.toggle=function(){this.isChecked?this.countUp():this.countDown()},e.prototype.animate=function(t,e){var n=this,o=0,i=function(r){o||(o=r);var a=Math.min((r-o)/n.duration,1);n.el.innerText=String(Math.floor(a*(e-t)+t)),a<1&&window.requestAnimationFrame(i)};window.requestAnimationFrame(i)},e.prototype.countUp=function(){this.animate(this.min,this.max)},e.prototype.countDown=function(){this.animate(this.max,this.min)},e.getInstance=function(t,e){var n=window.$hsToggleCountCollection.find((function(e){return e.element.el===("string"==typeof t?document.querySelector(t):t)}));return n?e?n:n.element:null},e}(n(737).default);window.addEventListener("load",(function(){window.$hsToggleCountCollection||(window.$hsToggleCountCollection=[]),document.querySelectorAll("[data-hs-toggle-count]:not(.--prevent-on-load-init)").forEach((function(t){return new a(t)}))})),t.exports.HSToggleCount=a,e.default=a}},e={};return function n(o){var i=e[o];if(void 0!==i)return i.exports;var r=e[o]={exports:{}};return t[o].call(r.exports,r,r.exports,n),r.exports}(87)})()));