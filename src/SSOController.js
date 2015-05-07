sinaSSOController = new SSOController();
sinaSSOController.init();

function SSOController() {
    var me = this; // use in private function 
    var updateCookieTimer = null;
    var updateCookieTimeHardLimit = 1800; // �ڸ�ʱ���ڲ��������cookie��Ĭ��30����
    var cookieExpireTimeLength = 3600 * 24; // cookie����ʱ��Ϊ24Сʱ
    
    var crossDomainForward = null; // �㲥������ɺ�ִ�еĶ���
    var crossDomainTimer = null;
    var crossDomainTime = 3; // ����㲥���������ʱ��
    var autoLoginCallBack2 = null;
    
    var ssoCrosssDomainUrl = 'http://login.sina.com.cn/sso/crossdomain.php';
    var ssoLoginUrl = 'http://login.sina.com.cn/sso/login.php';
    var ssoLogoutUrl = 'http://login.sina.com.cn/sso/logout.php';
    var ssoUpdateCookieUrl = 'http://login.sina.com.cn/sso/updatetgt.php';
    var ssoPreLoginUrl = 'http://login.sina.com.cn/sso/prelogin.php';
    var ssoCheckAltLoginNameUrl = 'http://login.sina.com.cn/bindmail/checkmailuser.php';
    var pincodeUrl = 'http://login.sina.com.cn/cgi/pin.php';
    var vfValidUrl = 'http://weibo.com/sguide/vdun.php';
    
    var crossDomainUrlList = null;
    
    var loginMethod = ""; // post or get ,�����¼��Ĵ���
    var checkAltLoginNameCallbackData = {};
    var ssoCheckAltLoginNameScriptId = 'check_alt_login';
    
    var ssoServerTimeTimer = null;
    var ssoLoginTimer = null;
    
    var loginByConfig = null; // Ϊ�ٴε�¼ʹ��
    var loginMethodCheck = null; // Ϊ�ٴε�¼ʹ��
    
    var https = 1; //write only
    var rsa = 2; //write only
    var wsse = 4; //write only
    var pcid = ""; //pincode id
    
    var tmpData = {};
    
    var preloginTimeStart = 0;
    var preloginTime = 0;
    
    this.https = 1; //read only
    this.rsa = 2; //read only
    this.wsse = 4; //read only
    
    
    this.name = 'sinaSSOController';
    this.loginFormId = 'ssoLoginForm';
    this.scriptId = 'ssoLoginScript';
    this.ssoCrossDomainScriptId = 'ssoCrossDomainScriptId';
    this.loginFrameName = 'ssoLoginFrame';
    this.appLoginURL = {'51uc.com': 'http://passport.51uc.com/sso/login.php','weibo.com': 'http://weibo.com/sso/login.php'};
    this.appDomainService = {'51uc.com': '51uc','weibo.com': 'miniblog'};
    this.loginExtraQuery = {};

    //��Ҫ���õ�����
    this.setDomain = false; // Ϊ���¼����ṩ�Ŀ��������ԵĲ���
    this.feedBackUrl = '';
    this.service = 'sso';
    this.domain = 'sina.com.cn'; // sina.com.cn ��Ĳ�Ʒ������Ҫ������
    this.from = ''; // ����ľ�����Դ����entry������
    this.pageCharset = 'GB2312'; // ҳ��ı��룬��Ҫ��������֤,Ĭ��ΪGB2312
    this.useTicket = false; // ��¼�ɹ���ʧ�ܺ��Ƿ񷵻�ticket��Ĭ��Ϊfalse
    this.isCheckLoginState = false; // ��ʼ��ʱ�Ƿ����¼״̬, ��齫��feedBackUrl ,����Ĭ�ϲ����
    this.isUpdateCookieOnLoad = true; // �Ƿ��ڼ��ظ�js�ļ����Զ�����һ��cookie��Ĭ��Ϊ�Զ�����,����Զ����˻ص��������벻Ҫ�Զ�����cookie
    this.useIframe = true; // Ĭ��ʹ��iframe ��post��ʽ�ĵ�¼����������ṩfeedBackUrl��������ʹ�ø÷�ʽ,������ѡ��������ĵ���
    this.noActiveTime = 7200; // ����Ծʱ����Ĭ��2Сʱ
    this.autoUpdateCookieTime = 1800; // ҳ�治��ʱ�Զ�����cookie�ļ��ʱ��,Ĭ��30����,����5s��������
    this.loginType = rsa; // Ĭ��rsa��ʽ
    this.timeoutEnable = false;
    this.crossDomain = true; // default true
    this.scriptLoginHttps = false; // ��ʹ��post��ʽ��¼ʧ�ܺ�ת��Ϊscript��ǩ��ʽ�ĵ�¼�Ƿ�ǿ��ʹ��https�ķ�ʽ��¼,Ĭ��ʹ��wsse��ʽ��¼
    
    this.allowAutoFoundServerTime = false; //�Ƿ��Զ����ַ�������ʱ��,Ĭ�ϲ��Զ����֣����ٷǵ�¼ҳ��Ҳ��ʹ�ø�js����Щҳ��Ͳ����ķ�����ʱ����
    this.allowAutoFoundServerTimeError = true; //�Ƿ��Զ����ַ�������ʱ�����
    this.calcServerTimeInterval = 2000; //2s
    this.servertime = null;
    this.nonce = null;
    this.rsaPubkey = null;
    this.rsakv = null;
    
    this.loginExtraFlag = {};
    this.cdult = false;
    this.crossDomainTime = 5;
    this.failRedirect = false; //��������Ҫ��ת��ҳ��ʱ����ǰҳ���Ƿ�֧����ת��
    
    this.getVersion = function() {
        return "ssologin.js(v1.4.2) 2012-8-21";
    };
    this.getEntry = function() {
        return me["entry"];
    };
    this.getClientType = function() {
        return me.getVersion().split(' ')[0];
    };
    this.init = function() {
        me.setLoginType(me.loginType); // ����Ƿ���Ҫʹ��https
        var ssoConfig = window["sinaSSOConfig"];
        if (typeof ssoConfig != "object") {
            ssoConfig = {};
        }
        //maping config set
        var name;
        for (name in ssoConfig) {
            me[name] = ssoConfig[name];
        }
        if (!me["entry"])
            me["entry"] = me["service"];
        if (me.isUpdateCookieOnLoad) {
            setTimeout(me.name + ".updateCookie()", 10000);
        }

        //����feedBackUrl����¼״̬��feedBackUrl���ܻ�ת��ssoLoginUrlȡ״̬
        if (me.isCheckLoginState) {
            addEventListener(window, "load", function() {
                me.checkLoginState();
            });
        }
        //��ͼ��ҳ���з���ssoServerTime����Ϊ��¼�ĳ�ʼʱ��
        if (me.allowAutoFoundServerTime && ssoLoginServerTime)
            me.setServerTime(ssoLoginServerTime);
        me.customInit();
    
    };
    
    this.customInit = function() {
    };
    
    this.customUpdateCookieCallBack = function(result) {
    // ����Ҫ���ĸ÷���
    };
    this.customLogoutCallBack = function(result) {
        me.customLoginCallBack({"result": false});
    };

    /**
	 * �˺���Ϊ�û��ɸ��ǵĻص�������loginStatus����Ϊ�û��ĵ�¼״̬
	 * Ϊfalse��δ��¼
	 * �������ʾ�û��ĵ�¼��Ϣ����
	 */
    this.customLoginCallBack = function(loginStatus) {
    // �÷����ɲ�Ʒ�Լ�������
    };
    
    this.login = function(username, password, savestate) {
        if (!ssoLoginTimer) {
            ssoLoginTimer = new prototypeTimer(me.timeoutEnable);
        } else {
            ssoLoginTimer.clear();
        }
        ssoLoginTimer.start(5000, function() {
            ssoLoginTimer.clear(); // ������������ʱ�ӣ���ٵ��ĵ�¼��Ȼ����ʾ��¼���
            me.customLoginCallBack({"result": false,"reason": unescape("%u767B%u5F55%u8D85%u65F6%uFF0C%u8BF7%u91CD%u8BD5")});
        });
        savestate = savestate == undefined ? 0 : savestate;
        tmpData['savestate'] = savestate;
        loginByConfig = function() {
            if (me.useIframe && (me.setDomain || me.feedBackUrl)) {
                if (me.setDomain) {
                    document.domain = me.domain;
                    if (!me.feedBackUrl && me.domain != "sina.com.cn")
                        me.feedBackUrl = makeURL(me.appLoginURL[me.domain], {"domain": 1});
                }
                loginMethod = "post";
                var result = loginByIframe(username, password, savestate);
                if (!result) {
                    loginMethod = "get";
                    if (me.scriptLoginHttps) {
                        me.setLoginType(me.loginType | https);
                    } else {
                        me.setLoginType(me.loginType | rsa);
                    }
                    loginByScript(username, password, savestate);
                }
            } else {
                loginMethod = "get";
                loginByScript(username, password, savestate);
            }
            me.nonce = null;
        };
        loginMethodCheck = function() {
            if ((me.loginType & wsse) || (me.loginType & rsa)) {
                if (me.servertime) {
                    if (!me.nonce)
                        me.nonce = makeNonce(6);
                    loginByConfig();
                    return true;
                }
                // get servertime
                me.getServerTime(username, loginByConfig);
            } else {
                loginByConfig();
            }
        };
        loginMethodCheck();
        return true;
    };
    this.getServerTime = function(username, callback) {
        if (me.servertime) {
            if (typeof callback == "function")
                callback({"retcode": 0,"servertime": me.servertime});
            return true;
        }
        var url = location.protocol == "https:" ? ssoPreLoginUrl.replace(/^http:/, "https:") : ssoPreLoginUrl;

        //��username����base64����
        username = sinaSSOEncoder.base64.encode(urlencode(username));
        url = makeURL(url, {"entry": me.entry,"callback": me.name + ".preloginCallBack","su": username,"rsakt": "mod"});
        me.preloginCallBack = function(result) {
            if (result && result.retcode == 0) {
                me.setServerTime(result.servertime);
                me.nonce = result.nonce;
                me.rsaPubkey = result.pubkey;
                me.rsakv = result.rsakv;
                pcid = result.pcid;
                preloginTime = (new Date()).getTime() - preloginTimeStart;
            }
            if (typeof callback == "function")
                callback(result);
        };
        preloginTimeStart = (new Date()).getTime();
        excuteScript(me.scriptId, url);
    };
    this.logout = function() {
        try {
            var request = {'entry': me.getEntry(),'callback': me.name + '.ssoLogoutCallBack'};
            var url = location.protocol == "https:" ? ssoLogoutUrl.replace(/^http:/, "https:") : ssoLogoutUrl;
            url = makeURL(url, request);
            excuteScript(me.scriptId, url);
        } catch (e) {
        }
        return true;
    };
    this.ssoLogoutCallBack = function(result) {
        if (result.arrURL) {
            me.setCrossDomainUrlList(result);
        }
        me.crossDomainAction('logout', function() {
            me.customLogoutCallBack({'result': true});
        });
    };
    this.updateCookie = function() {
        try {
            if (me.autoUpdateCookieTime > 5) {
                if (updateCookieTimer != null) {
                    clearTimeout(updateCookieTimer);
                }
                updateCookieTimer = setTimeout(me.name + ".updateCookie()", me.autoUpdateCookieTime * 1000); // convert to millisecond
            }
            var cookieExpireTime = me.getCookieExpireTime();
            var now = (new Date()).getTime() / 1000; // convert to second
            var result = {};
            if (cookieExpireTime == null) { // cookie ������
                result = {"retcode": 6102}; // not login
            } else if (cookieExpireTime < now) { // cookie �Ѿ�����
                result = {"retcode": 6203}; // cookie expired
            } else if (cookieExpireTime - cookieExpireTimeLength + updateCookieTimeHardLimit > now) { // ��Ӳ���Ƶ�ʱ���ڲ��������cookie
                result = {"retcode": 6110};
            } else if (cookieExpireTime - now > me.noActiveTime) { // ����ڻ�������
                result = {"retcode": 6111};
            }
            if (result.retcode !== undefined) {
                me.customUpdateCookieCallBack(result);
                return false;
            }
            var url = location.protocol == "https:" ? ssoUpdateCookieUrl.replace(/^http:/, "https:") : ssoUpdateCookieUrl;
            url = makeURL(url, {"entry": me.getEntry(),"callback": me.name + ".updateCookieCallBack"});
            excuteScript(me.scriptId, url);
        } catch (e) {
        }
        return true;
    };
    // ������Ҫ�㲥�ĵ�ַ�б�
    this.setCrossDomainUrlList = function(urlList) {
        crossDomainUrlList = urlList;
    };

    // ����û����ı�ѡ��¼��ʽ
    // ���ҶԽӿڷ���ֵ����һЩ��װ��
    this.checkAltLoginNameCallback = function(data) {
        var ret = {'retcode': 0,'detail': '','data': ''};
        if (data.ret == "y") {
            ret['retcode'] = 1;
            ret['detail'] = '\u4e3a\u4e86\u60a8\u7684\u8d26\u53f7\u5b89\u5168\uff0c\u8bf7<a href="http://login.sina.com.cn/bindmail/signin.php?username=' + checkAltLoginNameCallbackData['username'] + '">\u7ed1\u5b9a\u90ae\u7bb1</a>';
            ret['data'] = checkAltLoginNameCallbackData['username'];
        } else if (data.ret == "n" && data.mail) {
            if (data.errcode == 'not_verify') {
                ret['retcode'] = 2;
                ret['detail'] = '\u60a8\u7684\u90ae\u7bb1: ' + data.mail + ' \u672a\u9a8c\u8bc1\uff0c\u70b9\u6b64<a href="http://login.sina.com.cn/bindmail/bindmail1.php?entry=sso&user=' + data.mail + '">\u91cd\u53d1\u9a8c\u8bc1\u90ae\u4ef6</a>';
                ret['data'] = data.mail;
            } else {
                ret['retcode'] = 3;
                ret['detail'] = '\u7528\u60a8\u7684\u90ae\u7bb1' + data.mail + '\u4e5f\u53ef\u4ee5\u767b\u5f55';
                ret['data'] = data.mail;
            }
        } else {
        // do nothing
        // and hide the wrong code returned by api. 
        }
        checkAltLoginNameCallbackData['callback'](ret);
    };
    
    this.checkAltLoginName = function(username, callback) {
        if (username == "") {
            return true;
        }
        var r = /^[0-9]{1,9}$/;
        if (r.exec(username)) {
            return true;
        }
        checkAltLoginNameCallbackData = {'username': username,'callback': callback};
        var url = (me.loginType & https) ? ssoCheckAltLoginNameUrl.replace(/^http:/, "https:") : ssoCheckAltLoginNameUrl;
        url = makeURL(url, {'name': username,'type': 'json','callback': 'sinaSSOController.checkAltLoginNameCallback'});
        excuteScript(ssoCheckAltLoginNameScriptId, url);
    };
    
    this.callFeedBackUrl = function(loginStatus) {
        try {
            var request = {'callback': me.name + ".feedBackUrlCallBack"};
            if (loginStatus['ticket']) {
                request['ticket'] = loginStatus['ticket'];
            }
            if (loginStatus['retcode'] !== undefined) {
                request['retcode'] = loginStatus['retcode'];
            }
            var url = makeURL(me.feedBackUrl, request);
            excuteScript(me.scriptId, url);
        } catch (e) {
        }
        return true;
    };
    // ��¼�ص�����,script��ǩ��¼��setDomain��ʽ��¼ʱʹ�øûص�����
    this.loginCallBack = function(result) {
        try {
            if (me.timeoutEnable && !ssoLoginTimer.isset())
                return;
            ssoLoginTimer.clear();
            me.loginExtraFlag = {}; //����뱾�ε�¼��صı�ʶ
            var loginStatus = {};
            var st = result["ticket"];
            var uid = result["uid"];
            if (uid) {
                loginStatus['result'] = true;
                loginStatus['retcode'] = 0;
                loginStatus['userinfo'] = {"uniqueid": result["uid"]};
                if (st)
                    loginStatus['ticket'] = st;
                if (me.feedBackUrl) {
                    if (me.crossDomain) {
                        me.crossDomainAction("login", function() {
                            me.callFeedBackUrl(loginStatus);
                        });
                    } else {
                        me.callFeedBackUrl(loginStatus);
                    }
                } else {
                    if (me.crossDomain) {
                        if (result["crossDomainUrlList"]) {
                            me.setCrossDomainUrlList({"retcode": 0,"arrURL": result["crossDomainUrlList"]});
                        }
                        me.crossDomainAction("login", function() {
                            if (st && me.appLoginURL[me.domain]) {
                                me.appLogin(st, me.domain, me.name + ".customLoginCallBack");
                            } else {
                                loginStatus["userinfo"] = objMerge(loginStatus["userinfo"], me.getSinaCookie());
                                me.customLoginCallBack(loginStatus);
                            }
                        });
                    } else {
                        me.customLoginCallBack(loginStatus);
                    }
                }
            } else {
                // ��������ʱ�����ò���ȷ���ݴ�
                if (loginMethodCheck && result['retcode'] == "2092" && me.allowAutoFoundServerTimeError) {
                    me.setServerTime(0); // ���÷�����ʱ���ֵ���������»�ȡ
                    me.loginExtraFlag = objMerge(me.loginExtraFlag, {"wsseretry": "servertime_error"}); // ������Ա�ʶ�������˽����
                    loginMethodCheck(); // ���µ�¼һ�Σ����û���˵�¼��ʱ�Ŀ����ˣ�ʵ�������鷳����û�б�Ҫ
                    loginMethodCheck = null; //������ѭ��
                    return false;
                }
                loginStatus['result'] = false;
                loginStatus['errno'] = result['retcode'];
                if (loginStatus['errno'] == '4069') { //������ת���ж�����֤
                    var reason = result['reason'].split('|');
                    loginStatus['reason'] = reason[0];
                    if (reason.length == 2)
                        loginStatus['rurl'] = reason[1];
                    if (loginStatus['rurl']) {
                        try {
                            top.location.href = loginStatus['rurl'];
                            return;
                        } catch (e) {
                        }
                    }
                } else {
                    loginStatus['reason'] = result['reason'];
                }
                me.customLoginCallBack(loginStatus);
            }
        } catch (e) {
        }
        return true;
    };
    this.updateCookieCallBack = function(result) {
        if (result['retcode'] == 0) {
            me.crossDomainAction("update", function() {
                me.customUpdateCookieCallBack(result);
            });
        } else { // ���Ը���ʧ�ܵ��������Ϊ����ʧ�ܺ�Ĳ������Ǳ����
            me.customUpdateCookieCallBack(result);
        }
    };
    this.feedBackUrlCallBack = function(result) {
        // ���ڸ���feedBackUrl������ǿ��get��ʽ��¼��ʱ�򣬼�ʱ����loginCallBack�ص�ʱ�Ѿ������
        if (loginMethod == "post" && me.timeoutEnable && !ssoLoginTimer.isset())
            return;
        ssoLoginTimer.clear();
        if (result.errno == "2092") {
            me.setServerTime(0); // ���÷�����ʱ���ֵ���������»�ȡ
        }
        if (result.errno == '4069') { // ��Ҫ��ת���ж�����֤
            var reason = result.reason.split('|');
            result.reason = reason[0];
            if (reason.length == 2) {
                result.rurl = reason[1];
                try {
                    top.location.href = result.rurl;
                    return;
                } catch (e) {
                }
            }
        }
        me.customLoginCallBack(result);
        removeNode(me.loginFrameName); // ɾ�������iframe,����һ����Ҫ�ڻص�ǰɾ����Firefox�����������
    };
    this.doCrossDomainCallBack = function(result) {
        me.crossDomainCounter++;
        if (result)
            removeNode(result.scriptId);
        if (me.crossDomainCounter == me.crossDomainCount) {
            clearTimeout(crossDomainTimer);
            me.crossDomainResult();
        }
    };
    this.crossDomainCallBack = function(result) {
        // ������ڻ�ȡ�㲥��ַ�б�������script��ǩ���������Ѿ��ù���ɾ��֮
        removeNode(me.ssoCrossDomainScriptId);
        if (!result || result.retcode != 0) {
            return false;
        }
        var arrURL = result.arrURL;
        var url, scriptId;
        var request = {'callback': me.name + '.doCrossDomainCallBack'};
        me.crossDomainCount = arrURL.length;
        me.crossDomainCounter = 0;
        if (arrURL.length == 0) { // �������Ҫ֪ͨ�κ���
            clearTimeout(crossDomainTimer);
            me.crossDomainResult();
            return true;
        }
        for (var i = 0; i < arrURL.length; i++) {
            url = arrURL[i];
            scriptId = 'ssoscript' + i;
            request.scriptId = scriptId;
            url = makeURL(url, request);
            if (isSafari()) {
                //safari ��Ҫ���������	// http://wiki.intra.sina.com.cn/pages/viewpage.action?pageId=6297546
                excuteIframe(scriptId, url);
            } else {
                excuteScript(scriptId, url);
            }
        
        }
    };
    
    this.crossDomainResult = function() {
        // ��չ㲥�б������´�����
        crossDomainUrlList = null;
        if (typeof crossDomainForward == 'function') {
            crossDomainForward();
        }
    };

    // �㲥��¼�¼�
    this.crossDomainAction = function(action, callback) {
        crossDomainTimer = setTimeout(me.name + '.crossDomainResult()', crossDomainTime * 1000);
        if (typeof callback == 'function') {
            crossDomainForward = callback;
        } else {
            crossDomainForward = null;
        }
        if (crossDomainUrlList) { // �Ѿ���������Ҫ�㲥�ĵ�ַ�б�
            me.crossDomainCallBack(crossDomainUrlList);
            return false;
        }
        // ��û����Ҫ�㲥�ĵ�ַ�б��Լ�ͨ��crossdomain.php ����ȡ
        var domain = me.domain;
        if (action == "update") {
            action = "login";
            domain = "sina.com.cn";
        }
        var request = {
            'scriptId': me.ssoCrossDomainScriptId,
            'callback': me.name + '.crossDomainCallBack',
            'action': action,
            'domain': domain
        };
        var url = makeURL(ssoCrosssDomainUrl, request);
        excuteScript(me.ssoCrossDomainScriptId, url);
    };
    this.checkLoginState = function(callback) {
        if (callback) {
            me.autoLogin(callback); // the arguments of callback is cookieinfo or null
        } else {
            me.autoLogin(function(cookieinfo) {
                var loginStatus = {};
                if (cookieinfo !== null) {
                    var userinfo = {
                        'displayname': cookieinfo['nick'],
                        'uniqueid': cookieinfo['uid'],
                        'userid': cookieinfo['user']
                    };
                    loginStatus["result"] = true;
                    loginStatus["userinfo"] = userinfo;
                } else {
                    loginStatus["result"] = false;
                    loginStatus["reason"] = "";
                }
                me.customLoginCallBack(loginStatus);
            });
        }
    };
    
    this.getCookieExpireTime = function() {
        return getCookieExpireTimeByDomain(me.domain);
    };
    this.getSinaCookie = function(strict) {
        var sup = urldecode(getCookie("SUP"));
        if (!sup && !urldecode(getCookie("ALF")))
            return null;
        if (!sup)
            sup = urldecode(getCookie("SUR"));
        if (!sup)
            return null;
        var arrSup = parse_str(sup);
        if (strict && arrSup["et"] && (arrSup["et"] * 1000 < (new Date()).getTime())) {
            return null;
        }
        return arrSup;
    };
    this.get51UCCookie = function() {
        return me.getSinaCookie();
    };
    this.autoLogin = function(callback) {
        if (me.domain == 'sina.com.cn') {
            if (getCookie('SUP') === null && getCookie('ALF') !== null) {
                sinaAutoLogin(callback);
                return true;
            }
        } else {
            if (getCookie('SUP') === null && (getCookie('SSOLoginState') !== null || getCookie('ALF') !== null)) {
                sinaAutoLogin(callback);
                return true;
            }
        }
        callback(me.getSinaCookie());
        return true;
    };
    this.autoLoginCallBack2 = function(result) {
        try {
            autoLoginCallBack2(me.getSinaCookie());
        } catch (e) {
        }
        return true;
    };
    this.appLogin = function(ticket, domain, callback) {
        var savestate = tmpData['savestate'] ? parseInt((new Date()).getTime() / 1000 + tmpData['savestate'] * 86400) : 0;
        var alf = getCookie('ALF') ? getCookie('ALF') : 0;
        var request = {
            'callback': callback,
            'ticket': ticket,
            'ssosavestate': savestate || alf
        };
        
        var appLoginURL = me.appLoginURL[domain];
        var url = makeURL(appLoginURL, request);
        excuteScript(me.scriptId, url, "gb2312");
        return true;
    };
    this.autoLoginCallBack3 = function(result) {
        if (result['retcode'] != 0) {
            me.autoLoginCallBack2(result);
            return false;
        }
        me.appLogin(result["ticket"], me.domain, me.name + ".autoLoginCallBack2");
        return true;
    };
    this.setLoginType = function(loginType) {
        // ��鵱ǰҳ���Ƿ�https������ǣ���ǿ��ʹ��https��¼���������������ʾ
        var https = location.protocol == "https:" ? me.https : 0;
        if (https)
            me.crossDomain = false;
        me.loginType = loginType | https;
        return true;
    };
    this.setServerTime = function(servertime) {
        if (!ssoServerTimeTimer) {
            ssoServerTimeTimer = new prototypeTimer(true);
        }
        // ���÷�����ʱ��
        if (servertime == 0) {
            ssoServerTimeTimer.clear();
            me.servertime = servertime;
            return true;
        }
        // �������ò����׵�ʱ��
        if (servertime < 1294935546)
            return false;
        var calcServerTime = function() {
            if (me.servertime) {
                me.servertime += me.calcServerTimeInterval / 1000;
                ssoServerTimeTimer.start(me.calcServerTimeInterval, calcServerTime);
            }
        };
        me.servertime = servertime;
        ssoServerTimeTimer.start(me.calcServerTimeInterval, calcServerTime);
    };
    
    this.getPinCodeUrl = function(size) {
        if (size == undefined) {
            size = 0;
        }
        if (pcid) {
            me.loginExtraQuery.pcid = pcid;
        }
        var url = location.protocol == "https:" ? pincodeUrl.replace(/^http:/, "https:") : pincodeUrl;
        return url + '?r=' + Math.floor(Math.random() * 100000000) + '&s=' + size + (pcid.length > 0 ? '&p=' + pcid : '');
    };
    
    this.showPinCode = function(id) {
        me.$(id).src = me.getPinCodeUrl();
    };
    
    this.isVfValid = function() {
        return me.getSinaCookie(true)['vf'] != 1;
    };
    
    this.getVfValidUrl = function() {
        return vfValidUrl;
    };
    
    this.enableFailRedirect = function() {
        me.failRedirect = true;
    };
    
    var makeNonce = function(len) {
        var x = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var str = "";
        for (var i = 0; i < len; i++) {
            str += x.charAt(Math.ceil(Math.random() * 1000000) % x.length);
        }
        return str;
    };
    var sinaAutoLogin = function(callback) {
        autoLoginCallBack2 = callback;
        var request = {
            'entry': me.getEntry(),
            'service': me.service,
            'encoding': 'UTF-8',
            'gateway': 1,
            'returntype': 'TEXT',
            'from': me.from
        };
        if (me.domain == 'sina.com.cn') {
            request['callback'] = me.name + '.autoLoginCallBack2';
            request['useticket'] = 0;
        } else {
            request['callback'] = me.name + '.autoLoginCallBack3';
            request['useticket'] = 1;
        }
        
        var url = location.protocol == "https:" ? ssoLoginUrl.replace(/^http:/, "https:") : ssoLoginUrl;
        url = makeURL(url, request);
        excuteScript(me.scriptId, url, "gb2312");
        return true;
    };
    var getCookieExpireTimeByDomain = function(domain) {
        var expireTime = null;
        var cookie = null;
        cookie = me.getSinaCookie();
        if (cookie)
            expireTime = cookie['et'];
        return expireTime;
    };
    var addEventListener = function(dom, eventName, fn) {
        if (dom.addEventListener) {
            dom.addEventListener(eventName, fn, false);
        } else if (dom.attachEvent) {
            dom.attachEvent("on" + eventName, fn);
        } else {
            dom["on" + eventName] = fn;
        }
    };
    var prototypeTimer = function(enable) {
        var mytimer = false;
        this.start = function(timeout, callback) {
            if (enable)
                mytimer = setTimeout(callback, timeout);
        };
        this.clear = function(name) {
            if (enable) {
                clearTimeout(mytimer);
                mytimer = false;
            }
        };
        this.isset = function() {
            return mytimer !== false;
        };
    };

    // �˺�������ִ��һ��script
    var excuteScript = function(id, scriptSource, charset) {
        removeNode(id);
        var head = document.getElementsByTagName('head')[0];
        var newScript = document.createElement('script');
        newScript.charset = charset || 'gb2312';
        newScript.id = id;
        newScript.type = 'text/javascript';
        newScript.src = makeURL(scriptSource, {"client": me.getClientType(),"_": (new Date()).getTime()});
        head.appendChild(newScript);
    };

    //�˺������ڽ���һ��iframe����
    var excuteIframe = function(id, url) {
        removeNode(id);
        var bodyel = document.getElementsByTagName('body')[0];
        var new_iframe = document.createElement('iframe');
        new_iframe.style.display = 'none';
        new_iframe.src = makeURL(url, {"client": me.getClientType(),"_": (new Date()).getTime()});
        new_iframe.isReady = false;
        addEventListener(new_iframe, 'load', function() {
            if (new_iframe.isReady) {
                return;
            }
            new_iframe.isReady = true;
            me.doCrossDomainCallBack({scriptId: id});
        });
        bodyel.appendChild(new_iframe);
    };
    
    var makeRequest = function(username, password, savestate) {
        var request = {
            "entry": me.getEntry(),
            "gateway": 1,
            "from": me.from,
            "savestate": savestate,
            "useticket": me.useTicket ? 1 : 0
        };
        if (me.failRedirect) {
            me.loginExtraQuery.frd = 1;
        }
        request = objMerge(request, me.loginExtraFlag);
        request = objMerge(request, me.loginExtraQuery);
        request["su"] = sinaSSOEncoder.base64.encode(urlencode(username)); // su��username�ı���
        if (me.service)
            request["service"] = me.service;
        if ((me.loginType & rsa) && me.servertime && sinaSSOEncoder && sinaSSOEncoder.RSAKey) {
            request["servertime"] = me.servertime;
            request["nonce"] = me.nonce;
            request["pwencode"] = "rsa2";
            request["rsakv"] = me.rsakv;
            var RSAKey = new sinaSSOEncoder.RSAKey();
            RSAKey.setPublic(me.rsaPubkey, '10001');
            password = RSAKey.encrypt([me.servertime, me.nonce].join("\t") + "\n" + password);
        } else if ((me.loginType & wsse) && me.servertime && sinaSSOEncoder && sinaSSOEncoder.hex_sha1) {
            request["servertime"] = me.servertime;
            request["nonce"] = me.nonce;
            request["pwencode"] = "wsse";
            password = sinaSSOEncoder.hex_sha1("" + sinaSSOEncoder.hex_sha1(sinaSSOEncoder.hex_sha1(password)) + me.servertime + me.nonce); // ���ַ���Ϊ�˱������ȫ��������ʱ���������Ӷ������ַ������ӵ����
        }
        request["sp"] = password; // sp��password�ı���
        return request;
    };
    // login by script
    var loginByScript = function(username, password, savestate) {
        if (me.appLoginURL[me.domain]) {
            me.useTicket = 1;
            me.service = me.appDomainService[me.domain] || me.service; // UNITE-695
        }
        var cdult = 0;
        if (me.domain)
            cdult = 2;
        if (!me.appLoginURL[me.domain])
            cdult = 3;
        if (me.cdult !== false) {
            cdult = me.cdult;
        }
        if (cdult == 3) {
            crossDomainTime = me.crossDomainTime;
            delete me.appLoginURL[me.domain];
        }
        var request = makeRequest(username, password, savestate);
        request = objMerge(request, {
            "encoding": "UTF-8",
            "callback": me.name + ".loginCallBack",
            "cdult": cdult, // return crossdomain url list
            "domain": me.domain,
            "useticket": me.appLoginURL[me.domain] ? 1 : 0,
            "prelt": preloginTime,
            "returntype": "TEXT"
        });
        var url = (me.loginType & https) ? ssoLoginUrl.replace(/^http:/, "https:") : ssoLoginUrl;
        url = makeURL(url, request);
        excuteScript(me.scriptId, url, "gb2312");
    };
    // login by iframe
    var loginByIframe = function(username, password, savestate) {
        createIFrame(me.loginFrameName);
        var loginForm = createForm(me.loginFormId);
        var request = makeRequest(username, password, savestate);
        
        request["encoding"] = "UTF-8";
        if (me.crossDomain == false) {
            request["crossdomain"] = 0;
        }
        request["prelt"] = preloginTime;
        
        if (me.feedBackUrl) {
            request["url"] = makeURL(me.feedBackUrl, {"framelogin": 1,"callback": "parent." + me.name + ".feedBackUrlCallBack"});
            request["returntype"] = "META";
        } else {
            request["callback"] = "parent." + me.name + ".loginCallBack";
            request["returntype"] = "IFRAME";
            request["setdomain"] = me.setDomain ? 1 : 0;
        }
        
        for (var key in me.loginExtraQuery) {
            if (typeof me.loginExtraQuery[key] == "function")
                continue;
            request[key] = me.loginExtraQuery[key];
        }
        for (var name in request) {
            loginForm.addInput(name, request[name]);
        }
        
        var action = (me.loginType & https) ? ssoLoginUrl.replace(/^http:/, "https:") : ssoLoginUrl;
        action = makeURL(action, objMerge({"client": me.getClientType()}, me.loginExtraFlag));
        
        loginForm.method = 'post';
        loginForm.action = action;
        loginForm.target = me.loginFrameName;
        
        var result = true;
        try {
            loginForm.submit();
        } catch (e) {
            removeNode(me.loginFrameName);
            result = false;
        }
        setTimeout(function() {
            removeNode(loginForm);
        }, 10);
        return result;
    };
    // ����Iframe
    var createIFrame = function(frameName, src) {
        if (src == null)
            src = "javascript:false;";
        removeNode(frameName);
        var frame = document.createElement('iframe');
        frame.height = 0;
        frame.width = 0;
        frame.style.display = 'none';
        frame.name = frameName;
        frame.id = frameName;
        
        frame.src = src;
        appendChild(document.body, frame);
        window.frames[frameName].name = frameName;
        return frame;
    };

    // ����form��
    var createForm = function(formName, display) {
        if (display == null)
            display = 'none';
        // ȷ����Ψһ
        removeNode(formName);
        var form = document.createElement('form');
        form.height = 0;
        form.width = 0;
        form.style.display = display;
        form.name = formName;
        form.id = formName;
        appendChild(document.body, form);
        document.forms[formName].name = formName;

        // ���һ�����Ԫ�صķ���
        form.addInput = function(name, value, type) {
            if (type == null)
                type = 'text';
            var _name = this.getElementsByTagName('input')[name];
            if (_name) { // �����ظ����
                this.removeChild(_name);
            }
            _name = document.createElement('input');
            this.appendChild(_name);
            _name.id = name;
            _name.name = name;
            _name.type = type;
            _name.value = value;
        };
        return form;
    };
    //ɾ��DOMԪ��
    var removeNode = function(el) {
        try {
            if (typeof (el) === 'string')
                el = me.$(el);
            el.parentNode.removeChild(el);
        } catch (e) {
        }
    };
    //�ж��Ƿ�Ϊ safari �����
    var isSafari = function() {
        var browserName = navigator.userAgent.toLowerCase();
        return ((/webkit/i).test(browserName) && !(/chrome/i).test(browserName));
    };
    var appendChild = function(parentObj, element) {
        parentObj.appendChild(element);
    };
    //cookie ����
    var getCookie = function(name) {
        var Res = eval('/' + name + '=([^;]+)/').exec(document.cookie);
        return Res == null ? null : Res[1];
    };
    var makeURL = function(url, request) {
        return url + urlAndChar(url) + httpBuildQuery(request);
    };
    var urlAndChar = function(url) {
        return (/\?/.test(url) ? "&" : "?");
    };
    var urlencode = function(str) {
        return encodeURIComponent(str);
    };
    var urldecode = function(str) {
        if (str == undefined)
            return "";
        var decoded = decodeURIComponent(str);
        return decoded == "null" ? "" : decoded;
    };
    var httpBuildQuery = function(obj) {
        if (typeof obj != "object")
            return "";
        var arr = new Array();
        for (var key in obj) {
            if (typeof obj[key] == "function")
                continue;
            arr.push(key + "=" + urlencode(obj[key]));
        }
        return arr.join("&");
    };
    var parse_str = function(str) {
        var arr = str.split("&");
        var arrtmp;
        var arrResult = {};
        for (var i = 0; i < arr.length; i++) {
            arrtmp = arr[i].split("=");
            arrResult[arrtmp[0]] = urldecode(arrtmp[1]);
        }
        return arrResult;
    };
    var objMerge = function(obj1, obj2) {
        for (var item in obj2) {
            obj1[item] = obj2[item];
        }
        return obj1;
    };
    // ��ȡԪ�ض���
    this.$ = function(id) {
        return document.getElementById(id);
    };

}