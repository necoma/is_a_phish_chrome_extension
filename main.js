var myname;
var dialog_selector;
var watch_event_targets;
var isAPhishURL;
var isAPhishSimpleURL;
var timeout_millisecond;
var give_up_millisecond;
var form_data_list;
var isAPhishCache;
var isAPhishSimpleCache;
var startTime;
var is_timeout;
var is_on_event_got;
var is_show_addressbar;
var give_up_timer;
var eye_check_timer;
var isAPhishPassList;
document.OnLoad = start();

function InitializeGlobalValues(){
    myname = "CHROME_EXTENSION_BLACKLIST_WARNING";
    dialog_selector = myname + "_DIALOG";

    // 監視するイベントの名前(jQueryのもの)
    watch_event_targets = ["click", "change", "keypress", "mousedown"];

    isAPhishURL = "https://phishcage.nc.u-tokyo.ac.jp/cgi-bin/is_a_phish.cgi";
    isAPhishSimpleURL = "https://phishcage.nc.u-tokyo.ac.jp/cgi-bin/is_a_phish_simple.cgi";

    // 視線チェックを行う間隔
    timeout_millisecond = 1 * 1000; // 1秒

    // 視線や入力が無い場合のタイムアウト時間
    give_up_millisecond = 5 * 1000; // 5秒

    // disable される form
    form_data_list = {};

    // is_a_phish を叩いた時の結果のキャッシュ
    isAPhishCache = undefined;
    isAPhishSimpleCache = undefined;

    // 測定開始時刻
    startTime; // new Date();

    // 5秒経ったかどうかのフラグ
    is_timeout = false;
    // on* event が来たかどうかのフラグ
    is_on_event_got = false;
    // アドレスバーを見たかどうかのフラグ
    is_show_addressbar = false;

    // 5秒のタイマ
    give_up_timer = undefined;
    // 視線チェックのタイマ
    eye_check_timer = undefined;

    // is_a_phish を叩いた結果、ここに指定された値であれば form の disable を解除して良いとする(初期値は何も設定されない)
    isAPhishPassList = [];
}


// JSON で get request を出し/受け取ります。
function GetJSON(url, data, success_func, error_func){
    $.ajax({url: url,
	    type: "GET",
	    data: data,
	    dataType: 'json',
	    success: success_func,
	    error: error_func
	   });
}

// is_a_phish を叩いて結果を success_func に伝えます。
function CheckIsAPhish(check_target_url, success_func, error_func){
    GetJSON(isAPhishURL + "?url=" + encodeURIComponent(check_target_url), {}, success_func, error_func);
}
function CheckIsAPhishSimple(check_target_url, success_func, error_func){
    GetJSON(isAPhishSimpleURL + "?url=" + encodeURIComponent(check_target_url), {}, success_func, error_func);
}

// is_a_phish で受け取った値の confidence を確認します。
function checkPhish(is_a_phish_result, confidence_target_list){
    if("category" in is_a_phish_result && is_a_phish_result["category"] != "phish"){
	return false;
    }
    if(!("confidence" in is_a_phish_result)){
	return false;
    }
    confidence = is_a_phish_result["confidence"];
    if(confidence_target_list.indexOf(confidence) >= 0){
	return true;
    }
    return false;
}

// 現在の状態を評価して FORM を disable にするべきか enable にするべきかを判定する。
// 未定義の状態の場合は undefined を返す。
// それぞれ "disable", "enable", "undefined" という文字列を返す。
function CheckFormsFromCurrentState(){
    if(is_timeout) {
	// 5秒経っているので、is_a_phish で判定(low, medium で解除)
	if(isAPhishCache){
	    if(checkPhish(isAPhishCache, ["low", "medium"])){
		console.log("5 sec, not phish:", isAPhishCache);
		return "enable";
	    }
	    console.log("5 sec, is phish:", isAPhishCache);
	    return "disable";
	}else{
	    // isAPhishCache が無い場合は 5秒 経っているので timeout として enable を返す。
	    console.log("5 sec, is a phish timeout");
	    return "enable";
	}
    }
    // 以下5秒経ってない状態
    if(is_show_addressbar){
	// アドレスバーを見たので、is_a_phish_simple で判定(low, medium で解除)
	if(isAPhishSimpleCache){
	    if(checkPhish(isAPhishSimpleCache, ["low", "medium"])){
		console.log("address bar watched., not phish", isAPhishSimpleCache);
		return "enable";
	    }
	    console.log("address bar watched. phish", isAPhishSimpleCache);
	    return "disable";
	}else{
	    // アドレスバーを見た上で isAPhishSimple の結果が出てない場合は未定義状態
	    console.log("address bar watched. but isAPhishSimple is not completed.");
	    return "undefined";
	}
    }

    if(is_on_event_got){
	// on* event が来た → is_a_phish で判定(low のみで解除)
	if(isAPhishCache){
	    if(checkPhish(isAPhishCache, ["low"])){
		console.log("on* event got. not phish", isAPhishCache);
		return "enable";
	    }
	    console.log("on* event got. is phish", isAPhishCache);
	    return "disable";
	}else{
	    // isAPhish の結果が出てない場合は未定義状態
	    console.log("on* event got. but isAPhish request is not completed.", isAPhishCache);
	    return "undefined";
	}
    }

    console.log("check unknown", "is_timeout", is_timeout, "is_show_addressbar", is_show_addressbar, "is_on_event_got", is_on_event_got, "isAPhishCache", isAPhishCache, "isAPhishSimpleCache", isAPhishSimpleCache);
    return "undefined";
}

// 現在の状態から、フォームを Enable, Disable するべきならそのようにし、監視イベントを削除します。
function UpdateFormsFromCurrentState(){
    var result = CheckFormsFromCurrentState();
    if(result == "enable"){
	EnableAttribute(form_data_list);
	ClearEventHandler();
    }
    if(result == "disable"){
	DisableAttribute(form_data_list);
	ClearEventHandler();
	ShowAlertWithEnableFormButton("This site is more likely to be phishing site.", "PHISHING SITE WARNING");
    }
}

// 待ち受けているイベントハンドラをすべてクリアします
function ClearEventHandler(){
    if(eye_check_timer){
	clearTimeout(eye_check_timer);
    }
    if(give_up_timer){
	clearTimeout(give_up_timer);
    }
    RemoveOnStarEvent(form_data_list, OnStarEventHandler);
}

// on* イベントのイベントハンドラ
function OnStarEventHandler(data){
    //console.log("on* event got", data);
    is_on_event_got = true;
    UpdateFormsFromCurrentState();
}

// onClick, onChange, onMouseDown, onKeyPress イベントを指定されたタグに注入します
function InjectOnStarEvent(target_forms, event_handler_func){
    var watch_event_targets = ["click", "change", "keypress", "mousedown"];
    for(var i = 0; i < watch_event_targets.length; i++){
	var event_name = watch_event_targets[i];
	$(target_forms).bind(event_name, event_handler_func);
    }
}

function RemoveOnStarEvent(target_forms, event_handler_func){
    var watch_event_targets = ["click", "change", "keypress", "mousedown"];
    for(var i = 0; i < watch_event_targets.length; i++){
	var event_name = watch_event_targets[i];
	$(target_forms).unbind(event_name, event_handler_func);
    }
}

function ShowModalAlert(message, title){
    //alert(message);
    var arg = {
	text: message,
	type: 'error'
    };
    if(title){
	arg['title'] = title;
    }
    new PNotify(arg);
}

function ShowAlertWithEnableFormButton(message, title, form_data_list){
    if(window.confirm(message) == true){
	EnableAttribute(form_data_list);
    }else{
	//EnableAttribute(form_data_list);
    }
    return;
}

// $("form *") を受け取って、その disabled アトリビュートの設定を保存したリストにして返します。
function CreateFormAttributeDataList(form_list){
  var data_list = [];
  form_list.each(function(){
    var data = {};
    data['obj'] = this;
    data['disabled'] = $(this).attr('disabled');
    data_list.push(data);
  });
  return data_list;
}

// $("form *") 等で得られたもののリストを使って form を disable にします。
function DisableAttribute(form_data_list){
  for(var i in form_data_list){
    var v = form_data_list[i];
    var obj = v['obj'];
    //var disabled = v['disabled'];
    $(obj).attr('disabled', 'disabled');
  }
}
// $("form *") 等で得られたもののリストを使って form を enable にします。
function EnableAttribute(form_data_list){
  for(var i in form_data_list){
    var v = form_data_list[i];
    var obj = v['obj'];
    var disabled = v['disabled'];
    if(disabled != "disabled"){
      $(obj).removeAttr('disabled');
    }
  }
}

// EyeTrack の情報を取得して、それらしく動作します。
// このバージョンでは、目線が一回でも通ったら form を enable にして終了です。
function CheckEyeTrack(form_data_list, startTime){
    GetJSON("https://localhost:8888/check_fixation.json" + "?delta_millisecond=" + (new Date() - startTime)
	    , {}
	    , function(data){
		var hit = false;
		for(var key in data){
		    if(data[key]){
			hit = true;
			break;
		    }
		}
		if(hit){
		    // 視線がそちらに泳いだので、アドレスバーを見たフラグをつけて状態を更新します。
		    //console.log(form_data_list);
		    is_show_addressbar = true;
		    //console.log("is show addressbar.");
		    UpdateFormsFromCurrentState();
		}else{
		    // hit していないので、もう1秒待って再度視線チェックを行います。
		    eye_check_timer = setTimeout(function(){CheckEyeTrack(form_data_list, startTime);}, timeout_millisecond);
		}
	    }, function(){
		console.log("WARNING: check request failed. eyetribe server is not running? enable forms.");
		// チェッカが失敗したので enable にして終了とします。
		EnableAttribute(form_data_list);
		ClearEventHandler();
		ShowAlertWithEnableFormButton("Eyebit server is not responed.\nPlease check Eyebit server.", "Fatal error");
	    }
	   );
}

function start(){
    // PNotify を jQueryUI で初期化しておきます
    //PNotify.prototype.options.styling = "jqueryui";

    InitializeGlobalValues();

    // form の初期状態を拾います。
    form_data_list = CreateFormAttributeDataList($("form *"));

    // form_data_list の数が 0 なら何もする必要がありません。
    if(form_data_list.length <= 0){
	return;
    }

    // 問答無用で isAPhish をチェックしに行って、
    CheckIsAPhish(window.location, function(result){
	// 結果がphishingであると判定されたなら disable します。
	if(checkPhish(result, ["medium", "high"]) == true){
	    DisableAttribute(form_data_list);
	    ShowAlertWithEnableFormButton("This site is more likely to be phishing site. You need disable this page forms?", "PHISHING SITE WARNING");
	}
    });
}

