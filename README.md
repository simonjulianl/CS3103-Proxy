# CS3103 Programming Assignment

`proxy.py` is a simple web proxy that passes requests and data between a web client and a web server. The proxy is also able to do:
1. Telemetry
2. Image Substitution 
3. Attack mode

To run the proxy, use `python3 ./proxy.py <port> <image-flag> <attack-flag>`
- To print the help page, use `python3 ./proxy.py -h`
- Preferably, `python 3.10.6` is being used, but it has been tested with `python 3.8.10` in xcne server too.
- To enable logging, just comment `line 333` of the code.

These are the assumptions that I made during this assignment: 
### 1. Telemetry
1. The telemetry is distinguished using the `(host, port)` key. Therefore, if there are two browser sessions opening the
same tabs, the telemetry will be combined for both sessions. 
2. To determine that all the `GET` request from one browser session is done, for each request coming from the same `(host, port)` source, the proxy will 
wait for **_7.5s (purely based on heuristic)_** from the last request. If there isn't any new requests, the telemetry will be outputted. Therefore, if there are requests that are lagging so bad,
it is possible that it will be outputted under different telemetry. 
3. For Image Sub, I am counting the new image for the telemetry (i.e. `/change.jpg`) instead of the original image. Similarly, for the Attack mode, I am counting the artificial returned response 
that I have made into the telemetry instead of the original resource sizes. 
4. Only resource that is successfully fetched (i.e. `HTTP` response code `200`) would be counted towards telemetry.

### 2. Image Substitution
1. To determine whether the request is an image, I try to match it with common image file extensions such as `.jpeg, .jpg, .png, .svg, .gif`, etc. Moreover, 
I also check that if there are files that are requested and not substituted with `./change.jpg`, but the response has `Content-Type` of an image, I will consider it 
as an image too. This provides extra layer of protection to ensure all images are being subbed. However, there are still loopholes if `Content-Type` is either wrong or not present and the extension of the file requested is not one of the 
common image files.