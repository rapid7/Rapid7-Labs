---
title: Adobe Flash ByteArray Use-After-Free
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2015-07-08T14:59:00'
created: '2019-09-12T18:07:35.086266'
revision_date: '2020-02-13T17:12:13.532963'
assessment_id: 07ca799e-5951-4426-b75e-1c5b48ee4a81
topic_id: bdc2bc7e-5904-4c44-80ed-e26e3bd1a1a6
topic_short_id: jLhkepp0Dv
topic_slug: adobe-flash-bytearray-use-after-free
akb_topic_url: https://attackerkb.com/topics/jLhkepp0Dv/adobe-flash-bytearray-use-after-free
akb_assessment_url: https://attackerkb.com/topics/jLhkepp0Dv/adobe-flash-bytearray-use-after-free#07ca799e-5951-4426-b75e-1c5b48ee4a81
---

# Adobe Flash ByteArray Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/jLhkepp0Dv/adobe-flash-bytearray-use-after-free#07ca799e-5951-4426-b75e-1c5b48ee4a81).*

---

http://en.wikipedia.org/wiki/Adobe_Flash_Player

Congrats! You are reading about the most beautiful Flash bug for the last four
years since CVE-2010-2161.

The use-after-free vulnerability exists inside the built-in ByteArray class
http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/utils/ByteArray.html

Let's create a simple ByteArray object:

```
var ba:ByteArray = new ByteArray();
ba.length = 8;
ba[1] = 1;
```

Now we can access ba[] items and write numeric byte values into ba[].
Also we are allowed to write objects into ByteArray. For example:

```
var obj = new MyClass();
ba[0] = obj;
```

AS3 will try to implicitly convert the MyClass object into numeric value by
calling the MyClass.valueOf() method. This method can be easily redefined
within the user's code:

```
class MyClass
{
    prototype.valueOf = function()
    {
        ba.length = 88; // reallocate ba[] storage
        return 0;       // return byte for ba[offset]
    }
}
```

Let's see how that implicit conversion occurs inside the native code:

```
push esi
mov  eax, [esp+8]                // the offset value from "ba[offset] = obj"
push eax
add  ecx, 0x18                   // ecx = this = "ba" object pointer
call ByteArray.getStorage()      // gets ba[offset] storage pointer and
mov  esi, eax                    // saves it in esi

mov  ecx, [esp+0xC]              // "obj" pointer
push ecx
call AvmCore.toInteger()         // call MyClass.valueOf()
add  esp,4
mov  [esi], al                   // writes returned byte into array

pop  esi
ret  8
```

On high-level language this will look like:

```
void ByteArray.setObjInternal(int offset, obj)
{
    byte* dest = this.getStorage(offset);
    dest* = toInteger(obj);
}
```

So the array storage pointer is saved in local variable, then AS3 valueOf() is
invoked from the native code and returned byte is written into destination
pointer at the end. If valueOf() changes the length of byte array (see above)
and reallocates its internal storage, then local destination pointer becomes
obsolete and further usage of that pointer can lead to UaF memory corruption.

Using this vulnerability, it's very easy to control what byte will be written
and at which offset this corruption will occur.

3. AFFECTED SOFTWARE
Adobe Flash Player 9 and higher


4. TESTING
Open the test "calc.htm" file in your browser and press the button.

on Windows:
Calc.exe should be popped on desktop IE.
Calc.exe should be run as a non-GUI child process in metro IE.
Payload returns 0 from CreateProcessA("calc.exe") inside Chrome/FF sandbox.

on OS X:
Calculator is launched in FF or standalone Flash Player projector.
Payload returns 1 from vfork() in Safari sandbox.
