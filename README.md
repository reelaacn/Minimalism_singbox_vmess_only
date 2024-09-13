# tun_fakeip
This is a python script that supports creating "single-box for Android" profiles, you'll love it.

How to use:
1. you need to have [vmess/vless/ss/trojan/hysteria2] nodes address.
2. Write the nodes address list to nodes.txt.
3. Click the right mouse button, open mode "python3.1" and run "__main__.py".
4. The "tun.json" file is automatically generated at the end of the run, which is the configuration file required for single-box.
5. Place the "tun.json" file in the local "Windows IIS server" directory (Path:  C:\inetpub\wwwroot), so that you have a singbox subscription address.
    Example: http://192. 168. 0. 4/tun.json.
6. "config.json" is a single-box configuration template file, do not delete, do not rename.
   The "__main__.py" file is the main program, analyzes and extracts the processed node information, writes the processed node information into the configuration template, and finally generates the node configuration file "./ tun.json"。
	 "nodes.txt" is the node link storage file, do not delete, do not rename.
