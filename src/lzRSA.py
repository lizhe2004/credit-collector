#ending=utf-8
'''
Created on Dec 18, 2012

@author: lizhe2004
'''
import math

class RSAKey(object):
    '''
    classdocs
    '''
    

    def __init__(self):
        '''
        Constructor
        '''
 
        self.n = None
        self.e = 0;
        self.d = None
        self.p = None
        self.q = None
        self.dmp1 = None
        self.dmq1 = None
        self.coeff = None

    # Set the public key fields N and e from hex strings
    def  RSASetPublic(self,N, E) :
        if (N != None and E != None and len(N) > 0 and len(E) > 0) :
            self.n = self.parseBigInt(N, 16) 
            self.e =long(E, 16)
        else:
            return False;
        # convert a (hex) string to a bignum object
    def parseBigInt(self,szstr, r) :
        return  BigInteger(szstr, r)

    def linebrk(self,s, n) :
        ret = "";
        i = 0;
        while (i + n < len(s)): 
            ret += s[i, i + n] + "\n";
            i += n;
         
        return ret + s[i, len(s)];
   
    
    def byte2Hex(self,b)  :
        if (b < 0x10):
            return "0" + b.bnToString(16);
        else:
            return b.bnToString(16);
    

    #PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
    def pkcs1pad2(self,s, n) :
        if n < len(s) + 11 : #   fix for utf-8
            message =("Message too long for RSA");
            return None
    
        ba = range(n);
        i = len(s) - 1;
        while (i >= 0  and n > 0):
            t=i
            i-=1
            c = ord(s[t])

            if (c < 128) :# encode using utf-8
                n=n-1
                ba[n] = c;
             
            elif ((c > 127) and (c < 2048)):
                n=n-1
                ba[n] = (c & 63) | 128;
                n=n-1
                ba[n] = (c >> 6) | 192;
            
            else:
                n=n-1
                ba[n] = (c & 63) | 128;
                n=n-1
                ba[n] = ((c >> 6) & 63) | 128;
                n=n-1
                ba[n] = (c >> 12) | 224;
            
        n=n-1
        ba[n] = 0;
        rng = SecureRandom()
        x =[];
        x.append(0)
        while (n > 2) :# random non-zero pad
            x[0] = 0;
            while (x[0] == 0):
                rng.rng_get_bytes(x);
            n=n-1
            ba[n] = x[0];
        n=n-1
        ba[n] = 2;
        n=n-1
        ba[n] = 0;
#        ba=readtxt()
        return  BigInteger(ba);
 

    # Perform raw public operation on "x": return x^e (mod n)
    def RSADoPublic(self,x) :
        return x.bnModPowInt(self.e, self.n);
    


    # Return the PKCS#1 RSA encryption of "text" as an even-length hex string
    def RSAEncrypt(self,text):
        m = self.pkcs1pad2(text,(self.n.bnBitLength() + 7) >> 3)
        if (m == None):
            return None;
        c = self.RSADoPublic(m);
        if (c == None):
            return None;
        h = c.bnToString(16);
        if ((len(h) & 1) == 0):
            return h;
        else:
            return "0" + h;
        

import types


BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
BI_RC = {}
rr = ord("0")
for vv in range(10):
    BI_RC[rr] = vv;
    rr+=1
rr = ord("a")
for vv in range(10,36):
    BI_RC[rr] = vv
    rr+=1
rr = ord("A")
for vv in range(10,36):
    BI_RC[rr] = vv;
    rr+=1
 
dbits=28

    
BI_FP = 52;

class BigInteger:

    def __init__(self,a=None,b=None,c=None):
        '''
        Constructor
        '''
        self.DB = dbits;
        self.DM = ((1 << dbits) - 1);
        self.DV = (1 << dbits);
        self.FV = math.pow(2, BI_FP);
        self.F1 = BI_FP - dbits;
        self.F2 = 2 * dbits - BI_FP;
        
        self.value = {}
        if a is not None:
            if type(a) is types.IntType :
                self.fromNumber(a, b, c) 
            elif b is None and type(a) is not types.StringType:
                self.bnpFromString(a, 256);
            else:
                self.bnpFromString(a,b)

 
   
    def __getitem__(self, key):  
        return self.value[key];  
    def __setitem__(self, key, value):  
 
 
            self.value[key]=value
            
    def am(self,i, x, w, j, c, n):
        xl = x & 0x3fff
        xh = x >> 14;
        n-=1
        while (n >= 0) :
            l = self[i] & 0x3fff;
            h = self[i] >> 14
            i+=1
            m = xh * l + h * xl;
            l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w[j] = l & 0xfffffff;
            j+=1
            n-=1
        return c;
    
    
    def bnModPowInt(self,e,m):
        z=None;
        if (e < 256 or m.bnpIsEven()):
            z = Classic(m)
        else:
            z = Montgomery(m)
        return self.bnpExp(e, z);
    
# (protected) set from integer value x, -DV <= x < DV
    def bnpFromInt(self,x) :
        self.t = 1;
        if x<0:
            self.s = -1 
        else:
            self.s= 0;
        if (x > 0):
            self[0] = x;
        elif (x < -1):
            self[0] = x + self.DV;
        else:
            self.t = 0;
# (protected) set from string and radix
    def bnpFromString(self,s, b):
        k=0;
        if (b == 16):
            k = 4;
        elif (b == 8):
            k = 3;
        elif (b == 256):
            k = 8; # byte array
        elif (b == 2):
            k = 1;
        elif (b == 32):
            k = 5;
        elif (b == 4):
            k = 2;
        else :
            self.fromRadix(s, b);
            return;
 
        self.t = 0;
        self.s = 0;
        i = len(s)
        mi = False
        sh = 0;
        i=i-1
        while (i >= 0) :
            x =   s[i] & 0xff  if (k == 8)  else self.intAt(s, i);
            if (x < 0) :
                if (s[i] == "-"):
                    mi = True;
                i=i-1
                continue;
          
            mi = False;
            if (sh == 0):
                t =self.t
                self.t+=1
                self[t] = x;
            elif (sh + k > self.DB) :
                self[self.t - 1] |= (x & ((1 << (self.DB - sh)) - 1)) << sh;
                t =self.t
                self.t+=1
                self[t] = (x >> (self.DB - sh));
            else:
                self[self.t - 1] |= x << sh;
            sh += k;
            if (sh >= self.DB):
                sh -= self.DB;
            i=i-1
        if (k == 8 and (s[0] & 0x80) != 0):
            self.s = -1;
            if (sh > 0):
                self[self.t - 1] |= ((1 << (self.DB - sh)) - 1) << sh;
      
        self.bnpClamp();
        if (mi):
            ZERO.bnpSubTo(self, self);
            
            
    def int2char(self,n) :
        return BI_RM[n]
   
    def intAt(self,s, i) :
        c = BI_RC[ord(s[i])];
        return -1 if (c == None) else c;
    # (protected) clamp off excess high words
    def bnpClamp(self):
        c = self.s & self.DM;
        while (self.t > 0 and self[self.t - 1] == c):
            self.t=self.t-1;
            
    def bnpCopyTo(self,r):
        for  i in range(self.t):
            r[i] = self[i];
        r.t = self.t;
        r.s = self.s;
    # (public) return string representation in given radix
    def bnToString(self,b):
        if (self.s < 0):
            return "-" + self.bnNegate().toString(b);
        k=0;
        if (b == 16):
            k = 4;
        elif (b == 8):
            k = 3;
        elif (b == 2):
            k = 1;
        elif (b == 32):
            k = 5;
        elif (b == 4):
            k = 2;
        else:
            return self.toRadix(b);
        km = (1 << k) - 1
        m = False
        d=False
        r = ""
        i = self.t;
        p = self.DB - (i * self.DB) % k;
        t=i
        i-=1
        if (t > 0) :
            d = self[i] >> p
            if p < self.DB and d > 0 :
                m = True;
                r = self.int2char(d);
          
            while (i >= 0) :
                if (p < k) :
                    d = (self[i] & ((1 << p) - 1)) << (k - p);
                    p += self.DB - k
                    i=i-1
                    d |= self[i] >> p;
                 
                else :
                    p -= k
                    d = (self[i] >> (p)) & km;
                    if (p <= 0) :
                        p += self.DB;
                        i=i-1;
                  
             
                if (d > 0):
                    m = True;
                if (m):
                    r += self.int2char(d);
 
        return r if m else "0";
 
    
    def bnpInvDigit(self):
        if (self.t < 1):
            return 0;
        x = self[0];
        if ((x & 1) == 0):
            return 0;
        y = x & 3; # y == 1/x mod 2^2
        y = (y * (2 - (x & 0xf) * y)) & 0xf; # y == 1/x mod 2^4
        y = (y * (2 - (x & 0xff) * y)) & 0xff; # y == 1/x mod 2^8
        y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; # y == 1/x mod 2^16
        # last step - calculate inverse mod DV directly;
        # assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
        y = (y * (2 - x * y % self.DV)) % self.DV; # y == 1/x mod 2^dbits
        # we really want the negative inverse, and -DV < y < DV
        return self.DV - y if (y > 0) else -y;
 

    # (public) -this
    def bnNegate(self):
        r = nbi();
        ZERO.bnpSubTo(self, r);
        return r;
    

    # (public) |this|
    def bnAbs(self):
        return self.bnNegate()  if (self.s < 0) else self;
    

    # (public) return + if this > a, - if this < a, 0 if equal
    def bnCompareTo(self,a) :
        r = self.s - a.s;
        if (r != 0):
            return r;
        i = self.t;
        r = i - a.t;
        if (r != 0):
            return r;
        i=i-1
        while (i >= 0):
            r = self[i] - a[i]
            i=i-1
            if r != 0:
                return r;
        return 0;
  

    # returns bit length of the integer x
    def nbits(self,x) :
        r = 1
        t = x >> 16
        if ((t ) != 0) :
            x = t;
            r += 16;
        t = x >> 8
        if ((t  ) != 0) :
            x = t;
            r += 8;
        t = x >> 4
        if ((t ) != 0) :
            x = t;
            r += 4;
        t = x >> 2
        if ((t ) != 0) :
            x = t;
            r += 2;
        t = x >> 1
        if ((t ) != 0) :
            x = t;
            r += 1;
      
        return r;
 

    # (public) return the number of bits in "this"
    def bnBitLength(self): 
        if (self.t <= 0):
            return 0;
        return self.DB * (self.t - 1) + self.nbits(self[self.t - 1] ^ (self.s & self.DM));
 

    # (protected) r = this << n*DB
    def bnpDLShiftTo(self,n, r):
 
        for i in range(self.t):
            r[i + n] = self[i];
        for i in range( n):
            r[i] = 0;
        r.t = self.t + n;
        r.s = self.s;
  

    # (protected) r = this >> n*DB
    def bnpDRShiftTo(self,n, r) :
        for  i in range(n,self.t):
            r[i - n] = self[i];
        r.t = max(self.t - n, 0)
 
        r.s = self.s
 

    # (protected) r = this << n
    def bnpLShiftTo(self,n, r) :
        bs = n % self.DB;
        cbs = self.DB - bs;
        bm = (1 << cbs) - 1;
        
        ds =int( math.floor(n / self.DB))
        c = (self.s << bs) & self.DM;
        print range( self.t-1,-1,-1)
        for i in range( self.t-1,-1,-1) :
            r[i + ds + 1] = (self[i] >> cbs) | c;
            c = (self[i] & bm) << bs;
  
        for  i  in range( ds):
            r[i] = 0;
        r[ds] = c;
        r.t = self.t + ds + 1;
        r.s = self.s;
        r.bnpClamp();
 

    # (protected) r = this >> n
    def bnpRShiftTo(self,n, r):
        r.s = self.s;
        ds =int( math.floor(n / self.DB))
        if (ds >= self.t):
            r.t = 0;
            return;
        
        bs = n % self.DB;
        cbs = self.DB - bs;
        bm = (1 << bs) - 1;
        r[0] = self[ds] >> bs;
        for  i in range(ds + 1,self.t) :
            r[i - ds - 1] |= (self[i] & bm) << cbs;
            r[i - ds] = self[i] >> bs;
    
        if (bs > 0):
            r[self.t - ds - 1] |= (self.s & bm) << cbs;
        r.t = self.t - ds;
        r.bnpClamp();
 

    # (protected) r = this - a
    def bnpSubTo(self,a, r):
        i = 0
        c = 0
        m = min(a.t, self.t);
        while (i < m) :
            c += self[i] - a[i];
            t=i;
            i+=1
            r[t] = c & self.DM;
            c >>= self.DB;
      
        if (a.t < self.t) :
            c -= a.s;
            while (i < self.t) :
                c += self[i];
                t=i;
                i+=1
                r[t] = c & self.DM;
                c >>= self.DB;
 
            c += self.s;
       
        else :
            c += self.s;
            while (i < a.t) :
                c -= a[i];
                t=i;
                i+=1
                r[t] = c & self.DM;
                c >>= self.DB;
            
            c -= a.s;
        
        r.s = -1 if (c < 0) else 0;
        if (c < -1):
            t=i;
            i+=1
            r[t] = self.DV + c;
        elif (c > 0):
            t=i;
            i+=1
            r[t] = c;
        r.t = i;
        r.bnpClamp();
  

    # (protected) r = this * a, r != this,a (HAC 14.12)
    # "this" should be the larger one if appropriate.
    def bnpMultiplyTo(self,a, r) :
        x = self.bnAbs()
        y = a.bnAbs();
        i = x.t;
        r.t = i + y.t;
        i=i-1
        while (i >= 0):
            r[i] = 0;
            i=i-1
        for i in range( y.t):
            r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
        r.s = 0;
        r.bnpClamp();
        if (self.s != a.s):
            ZERO.bnpSubTo(r, r);
 

    # (protected) r = this^2, r != this (HAC 14.16)
    def bnpSquareTo(self,r):
        x = self.bnAbs();
        i = r.t = 2 * x.t;
        i=i-1
        while (i >= 0):
            r[i] = 0;
            i=i-1
        for i in range( x.t-1) :
            c = x.am(i, x[i], r, 2 * i, 0, 1);
            r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)
            if (r[i + x.t]  >= x.DV):
                r[i + x.t] -= x.DV;
                r[i + x.t + 1] = 1;
          
        i=x.t-1
        if (r.t > 0):
            r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
        r.s = 0;
        r.bnpClamp();
 

    # (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
# r != q, this != m.  q or r may be null.
    def bnpDivRemTo(self,m, q, r) :
        pm = m.bnAbs();
        if (pm.t <= 0):
            return;
        pt = self.bnAbs();
        if (pt.t < pm.t) :
            if (q != None):
                q.bnpFromInt(0);
            if (r != None):
                self.bnpCopyTo(r);
            return;
    
        if (r == None):
            r = nbi();
        y = nbi()
        ts = self.s
        ms = m.s;
        nsh = self.DB - self.nbits(pm[pm.t - 1]); # normalize modulus
        if (nsh > 0) :
            pm.bnpLShiftTo(nsh, y);
            pt.bnpLShiftTo(nsh, r);
       
        else :
            pm.bnpCopyTo(y);
            pt.bnpCopyTo(r);
        
        ys = y.t;
        y0 = y[ys - 1];
        if (y0 == 0):
            return;
        yt = y0 * (1 << self.F1) + (y[ys - 2] >> self.F2 if (ys > 1) else 0);
        d1 = self.FV / yt
        d2 = (1 << self.F1) / (float(yt))
        e = 1 << self.F2;
        i = r.t
        j = i - ys
        t = nbi() if (q == None) else q;
        y.bnpDLShiftTo(j, t);
        if (r.bnCompareTo(t) >= 0) :
            temp=r.t
            r.t+=1
            r[temp] = 1;
            r.bnpSubTo(t, r);
       
        ONE.bnpDLShiftTo(ys, t);
        t.bnpSubTo(y, y); # "negative" y so we can replace sub with am later
        while (y.t < ys):
            t=y.t
            y.t+=1
            y[t] = 0;
        j=j-1
        while (j >= 0) :
            # Estimate quotient digit
            qd = self.DM  
            i=i-1
            if (r[i] != y0):
                qd= int(math.floor(r[i] * d1 + (r[i - 1] + e) * d2));
            r[i] += y.am(0, qd, r, j, 0, ys)
            if ((r[i]) < qd) :# Try it out
                y.bnpDLShiftTo(j, t);
                r.bnpSubTo(t, r);
                qd=qd-1
                while (r[i] < qd):
                    r.bnpSubTo(t, r);
                    qd=qd-1
            j=j-1
        if (q != None) :
            r.bnpDRShiftTo(ys, q);
            if (ts != ms):
                ZERO.bnpSubTo(q, q);
      
        r.t = ys;
        r.bnpClamp();
        if (nsh > 0):
            r.bnpRShiftTo(nsh, r); # Denormalize remainder
        if (ts < 0):
            ZERO.bnpSubTo(r, r);
   

    # (public) this mod a
    def bnMod(self,a) :
        r = nbi();
        self.bnAbs().bnpDivRemTo(a, None, r);
        if (self.s < 0 and r.bnCompareTo(ZERO) > 0):
            a.bnpSubTo(r, r);
        return r;
 


    '''
    // (protected) return "-1/this % 2^DB"; useful for Mont. reduction
    // justification:
    //         xy == 1 (mod m)
    //         xy =  1+km
    //   xy(2-xy) = (1+km)(1-km)
    // x[y(2-xy)] = 1-k^2m^2
    // x[y(2-xy)] == 1 (mod m^2)
    // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
    // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
    // JS multiply "overflows" differently from C/C++, so care is needed here.
    '''
    

    # (protected) true iff this is even
    def bnpIsEven(self) :
        return ((self[0] & 1) if (self.t > 0)  else self.s) == 0;
    

    # (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
    def bnpExp(self,e, z) :
        if (e > 0xffffffff or e < 1):
            return ONE;
        r = nbi()
        r2 = nbi()
        g = z.convert(self)
        i = self.nbits(e) - 1;
        g.bnpCopyTo(r);
        i=i-1
        while (i >= 0) :
            z.sqrTo(r, r2);
            if ((e & (1 << i)) > 0):
                z.mulTo(r2, g, r);
            else :
                t = r;
                r = r2;
                r2 = t;
            i=i-1
     
        return z.revert(r);
def nbv(i):
    r = BigInteger()
    r.bnpFromInt(i);
    return r;
def nbi():
    return BigInteger()

ZERO = nbv(0)
ONE = nbv(1);
'''
(function() {


    /********************* jsbn.js start ************************/

    // Copyright (c) 2005  Tom Wu
    // All Rights Reserved.
    // See "LICENSE" for details.

    // Basic JavaScript BN library - subset useful for RSA encryption.

    // Bits per digit
    var dbits;

    // JavaScript engine analysis
    var canary = 0xdeadbeefcafe;
    var j_lm = ((canary & 0xffffff) == 0xefcafe);

 

    // return new, unset BigInteger
 

    // am: Compute w_j += (x*this_i), propagate carries,
    // c is initial carry, returns final carry.
    // c < 3*dvalue, x < 2*dvalue, this_i < dvalue
    // We need to select the fastest one that works in this environment.

    // am1: use a single mult and divide to get the high bits,
    // max digit bits should be 26 because
    // max internal value = 2*dvalue^2-2*dvalue (< 2^53)
    function am1(i, x, w, j, c, n) {
        while (--n >= 0) {
            var v = x * this[i++] + w[j] + c;
            c = Math.floor(v / 0x4000000);
            w[j++] = v & 0x3ffffff;
        }
        return c;
    }
    // am2 avoids a big mult-and-extract completely.
    // Max digit bits should be <= 30 because we do bitwise ops
    // on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
    function am2(i, x, w, j, c, n) {
        var xl = x & 0x7fff, xh = x >> 15;
        while (--n >= 0) {
            var l = this[i] & 0x7fff;
            var h = this[i++] >> 15;
            var m = xh * l + h * xl;
            l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
            c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
            w[j++] = l & 0x3fffffff;
        }
        return c;
    }
    // Alternately, set max digit bits to 28 since some
    // browsers slow down when dealing with 32-bit numbers.
    function am3(i, x, w, j, c, n) {
        var xl = x & 0x3fff, xh = x >> 14;
        while (--n >= 0) {
            var l = this[i] & 0x3fff;
            var h = this[i++] >> 14;
            var m = xh * l + h * xl;
            l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w[j++] = l & 0xfffffff;
        }
        return c;
    }
    if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
        BigInteger.prototype.am = am2;
        dbits = 30;
    } 
    else if (j_lm && (navigator.appName != "Netscape")) {
        BigInteger.prototype.am = am1;
        dbits = 26;
    } 
    else { // Mozilla/Netscape seems to prefer am3
        BigInteger.prototype.am = am3;
        dbits = 28;
    }
    
    BigInteger.prototype.DB = dbits;
    BigInteger.prototype.DM = ((1 << dbits) - 1);
    BigInteger.prototype.DV = (1 << dbits);
    
    var BI_FP = 52;
    BigInteger.prototype.FV = Math.pow(2, BI_FP);
    BigInteger.prototype.F1 = BI_FP - dbits;
    BigInteger.prototype.F2 = 2 * dbits - BI_FP;

    // Digit conversions
    var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
    var BI_RC = new Array();
    var rr, vv;
    rr = "0".charCodeAt(0);
    for (vv = 0; vv <= 9; ++vv)
        BI_RC[rr++] = vv;
    rr = "a".charCodeAt(0);
    for (vv = 10; vv < 36; ++vv)
        BI_RC[rr++] = vv;
    rr = "A".charCodeAt(0);
    for (vv = 10; vv < 36; ++vv)
        BI_RC[rr++] = vv;
    
    BigInteger.prototype.bnpCopyTo = bnpCopyTo;
    BigInteger.prototype.fromInt = bnpFromInt;
    BigInteger.prototype.FromString = bnpFromString;
    BigInteger.prototype.clamp = bnpClamp;
    BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
    BigInteger.prototype.drShiftTo = bnpDRShiftTo;
    BigInteger.prototype.lShiftTo = bnpLShiftTo;
    BigInteger.prototype.rShiftTo = bnpRShiftTo;
    BigInteger.prototype.subTo = bnpSubTo;
    BigInteger.prototype.multiplyTo = bnpMultiplyTo;
    BigInteger.prototype.squareTo = bnpSquareTo;
    BigInteger.prototype.divRemTo = bnpDivRemTo;
    BigInteger.prototype.invDigit = bnpInvDigit;
    BigInteger.prototype.isEven = bnpIsEven;
    BigInteger.prototype.exp = bnpExp;

    // public
    BigInteger.prototype.toString = bnToString;
    BigInteger.prototype.negate = bnNegate;
    BigInteger.prototype.abs = bnAbs;
    BigInteger.prototype.compareTo = bnCompareTo;
    BigInteger.prototype.bitLength = bnBitLength;
    BigInteger.prototype.mod = bnMod;
    BigInteger.prototype.modPowInt = bnModPowInt;

'''
class Montgomery:
    def __init__(self,m) :
        self.m = m;
        self.mp = m.bnpInvDigit();
        self.mpl = self.mp & 0x7fff;
        self.mph = self.mp >> 15;
        self.um = (1 << (m.DB - 15)) - 1;
        self.mt2 = 2 * m.t;
 

    # xR mod m
    def convert(self,x):
        r = nbi();
        x.bnAbs().bnpDLShiftTo(self.m.t, r);
        r.bnpDivRemTo(self.m, None, r);
        if (x.s < 0 and r.bnCompareTo(ZERO) > 0):
            self.m.bnpSubTo(r, r);
        return r;
 

    # x/R mod m
    def revert(self,x) :
        r = nbi();
        x.bnpCopyTo(r);
        self.reduce(r);
        return r;
   

    # x = x/R mod m (HAC 14.32)
    def reduce(self,x) :
        while (x.t <= self.mt2): #pad x so am has enough room later
            t=x.t
            x.t+=1
            x[t] = 0;
        for  i in range( self.m.t) :
            # faster way of calculating u0 = x[i]*mp mod DV
            j = x[i] & 0x7fff;
            u0 = (j * self.mpl + (((j * self.mph + (x[i] >> 15) * self.mpl) & self.um) << 15)) & x.DM;
            #use am to combine the multiply-shift-add into one call
            j = i + self.m.t;
            x[j] += self.m.am(0, u0, x, i, 0, self.m.t);
            # propagate carry
            while (x[j] >= x.DV):
                x[j] -= x.DV;
                j+=1
                x[j]+=1;
          
  
        x.bnpClamp();
        x.bnpDRShiftTo(self.m.t, x);
        if (x.bnCompareTo(self.m) >= 0):
            x.bnpSubTo(self.m, x);
 

# r = "x^2/R mod m"; x != r
    def sqrTo(self,x, r):
        x.bnpSquareTo(r);
        self.reduce(r);
 

    # r = "xy/R mod m"; x,y != r
    def mulTo(self,x, y, r) :
        x.bnpMultiplyTo(y, r);
        self.reduce(r);

 
    # Modular reduction using "classic" algorithm
class Classic:
    def __init__(self,m) :
        self.m = m;
    def convert(self,x): 
        if (x.s < 0 or x.bnCompareTo(self.m) >= 0):
            return x.bnMod(self);
        else:
            return x;
    def revert(self,x):
        return x;
    def reduce(self,x) :
        x.bnpDivRemTo(self.m, None, x);
     
    def mulTo(self,x, y, r) :
        x.bnpMultiplyTo(y, r);
        self.reduce(r);
   
    def sqrTo(self,x, r) :
        x.bnpSquareTo(r);
        self.reduce(r);
 
 
rng_psize = 256;

  
 
 
rng_state= None;
rng_pool=None;
rng_pptr=None



 
 


# Mix in a 32-bit integer into the pool
def rng_seed_int(x):
    global rng_pptr,rng_pool,rng_psize
    rng_pool[rng_pptr] ^= x & 255;
    rng_pptr+=1
    rng_pool[rng_pptr] ^= (x >> 8) & 255;
    rng_pptr+=1
    rng_pool[rng_pptr] ^= (x >> 16) & 255;
    rng_pptr+=1
    rng_pool[rng_pptr] ^= (x >> 24) & 255;
    rng_pptr+=1
    if (rng_pptr >= rng_psize):
        rng_pptr -= rng_psize;
 

# Mix in the current time (w/milliseconds) into the pool
def rng_seed_time():
    import datetime
    oldtime =datetime.datetime.strptime("1970-01-01","%Y-%m-%d")
    timenow = datetime.datetime.utcnow()
    microseconds = long((timenow - oldtime).total_seconds()*1000)
    rng_seed_int(microseconds);
    # Initialize the pool with junk if needed.
if (rng_pool == None):
    rng_pool = [];
    rng_pptr = 0;
 
    import random
    while (rng_pptr < rng_psize) : # extract some randomness from Math.random()
        t = int(math.floor(65536 *random.random()));
        rng_pool.append( t >> 8)
        rng_pptr+=1
        rng_pool.append ( t & 255)
        rng_pptr+=1
    
    rng_pptr = 0;
    rng_seed_time();
class Arcfour():
    def __init__(self):
        self.i = 0;
        self.j = 0;
        self.S = [];
 

# Initialize arcfour context from key, an array of ints, each from [0..255]
    def ARC4init(self,key) :
        i=0 
        t=0;
        for i in range( 256):
            self.S.append(i);
        j = 0;
        for i in range(256) :
            j = (j + self.S[i] + key[i %len( key)]) & 255;
            t = self.S[i];
            self.S[i] = self.S[j];
            self.S[j] = t;
   
        self.i = 0;
        self.j = 0;
 
    def ARC4next(self):
        self.i = (self.i + 1) & 255;
        self.j = (self.j + self.S[self.i]) & 255;
        t = self.S[self.i];
        self.S[self.i] = self.S[self.j];
        self.S[self.j] = t;
        return self.S[(t + self.S[self.i]) & 255];
 
 
class SecureRandom() :
    def __init__(self):
        pass
    def rng_get_bytes(self,ba) :
        for i in range(len(ba)):
            ba[i] = self.rng_get_byte();
    
    def rng_get_byte(self):
        global rng_state
        if (rng_state == None):
            rng_seed_time();
            rng_state =  Arcfour();
            rng_state.ARC4init(rng_pool);
            for rng_pptr in range(len( rng_pool)):
                rng_pool[rng_pptr] = 0;
            rng_pptr = 0;
        #rng_pool = null;
      
        #TODO: allow reseeding after first request
        return rng_state.ARC4next();
def readtxt():
    a=[]
    f = open("txt.txt")             
    index = f.readline()            
    numberdic={}
    while index:
                      
      
        number = f.readline()
        numberdic[int(index)]=int(number)
        print int(index), int(number)
        f.readline()
        index = f.readline()
    for i in range(len(numberdic)):
        a.append(numberdic[i])
        print a[i]
    return a
'''
readtxt()
a= RSAKey()
key="EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443"
key="EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443"
e="10001"
a.RSASetPublic(key,e)
 
password =""
#a.RSAEncrypt(password) 
'''





    
