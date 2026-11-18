// Traces StoreKit 1 purchases and receipt handling: addPayment (product, quantity, applicationUsername
// set or not), transaction state updates, finishTransaction, receipt URL access and receipt refresh.
// Use it to see whether unlocks happen before the server validates the receipt. StoreKit 2 is Swift
// async API and is not hooked here: confirm StoreKit 2 apps send Transaction.jwsRepresentation to the
// server (network_trace.js).
// Usage: frida -U -f <bundle> -l storekit_trace.js   (sandbox Apple ID only)
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
var STATE = { 0: "purchasing", 1: "purchased", 2: "failed", 3: "restored", 4: "deferred" };
function hook(cls, sel, cb) { var c = ObjC.classes[cls]; if (c && c[sel]) { Interceptor.attach(c[sel].implementation, cb); return true; } return false; }
var hookedObservers = {};
hook("SKPaymentQueue", "- addPayment:", { onEnter: function (a) {
  var p = new ObjC.Object(a[2]);
  emit({ type: "storekit", api: "addPayment", product: p.productIdentifier().toString(), quantity: p.quantity(),
         applicationUsername: p.applicationUsername() !== null, caller: bt(this.context) });
} });
hook("SKPaymentQueue", "- finishTransaction:", { onEnter: function (a) {
  var t = new ObjC.Object(a[2]);
  emit({ type: "storekit", api: "finishTransaction", state: STATE[t.transactionState()] || t.transactionState(), caller: bt(this.context) });
} });
hook("SKPaymentQueue", "- addTransactionObserver:", { onEnter: function (a) {
  var cn = new ObjC.Object(a[2]).$className;
  if (hookedObservers[cn]) return;
  hookedObservers[cn] = 1;
  hook(cn, "- paymentQueue:updatedTransactions:", { onEnter: function (b) {
    var ts = new ObjC.Object(b[3]);
    for (var i = 0; i < ts.count(); i++) {
      var t = ts.objectAtIndex_(i);
      emit({ type: "storekit", api: "updatedTransactions", observer: cn, state: STATE[t.transactionState()] || t.transactionState(),
             product: t.payment().productIdentifier().toString() });
    }
  } });
} });
hook("SKPaymentQueue", "- restoreCompletedTransactions", { onEnter: function () { emit({ type: "storekit", api: "restoreCompletedTransactions" }); } });
hook("NSBundle", "- appStoreReceiptURL", { onEnter: function () { this.c = bt(this.context); }, onLeave: function () { emit({ type: "storekit", api: "appStoreReceiptURL", caller: this.c }); } });
hook("SKReceiptRefreshRequest", "- start", { onEnter: function () { emit({ type: "storekit", api: "SKReceiptRefreshRequest.start" }); } });
hook("PKPaymentAuthorizationController", "- presentWithCompletion:", { onEnter: function () { emit({ type: "applepay", api: "present" }); } });
console.log("[storekit_trace] running");
