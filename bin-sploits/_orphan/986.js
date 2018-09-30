
var blockedReferrer = 'blockedReferrer';
NS_ActualWrite=document.write;
// Popup Blocker -->
RanPostamble=0;
NS_ActualOpen=window.open;
function NS_NullWindow(){this.window;}
function nullDoc() {
   this.open = NS_NullWindow;
   this.write = NS_NullWindow;
   this.close = NS_NullWindow;
}
function NS_NewOpen(url,nam,atr){
	if((nam!='' && nam==window.name) || nam=='_top'){
	   return(NS_ActualOpen(url,nam,atr));}
	obj=new NS_NullWindow();
	obj.focus = NS_NullWindow;
	obj.blur = NS_NullWindow;
	obj.opener = this.window;
	obj.document = new nullDoc();
	return(obj);
}
function NS_NullWindow2(){this.window;}
function NS_NewOpen2(url,nam,atr){
	if((nam!='' && nam==window.name) || nam=='_top'){
	   return(NS_ActualOpen(url,nam,atr));}
    return(new NS_NullWindow2());
}
function op_stop() { NS_ActualOpen2=window.open; window.open=NS_NewOpen2; }
function op_start() { window.open=NS_ActualOpen2; }
function noopen_load() { 
    op_stop(); if(zl_orig_onload) zl_orig_onload(); op_start();
}
function noopen_unload() { op_stop(); if(zl_orig_onunload) zl_orig_onunload(); op_start(); }
function postamble() {

  if(!RanPostamble) {
    RanPostamble=1;
	zl_orig_onload = window.onload;
	zl_orig_onunload = window.onunload;
	window.open=NS_ActualOpen;
  }
}
window.open=NS_NewOpen;
document.ignore = new Object();
