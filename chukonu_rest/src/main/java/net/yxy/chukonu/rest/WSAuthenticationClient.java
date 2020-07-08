package net.yxy.chukonu.rest;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

public class WSAuthenticationClient {
	
	public static boolean validateConnection(String authType, String url, String realm, String username, String password){
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		CloseableHttpClient httpclient = httpClientBuilder.build();
		URL urlObj = null;
		CloseableHttpResponse response = null;
		try {
			urlObj = new URL(url);
			HttpHost targetHost = new HttpHost(urlObj.getHost(), 80, "http");
			CredentialsProvider credsProvider = new BasicCredentialsProvider();
			credsProvider.setCredentials(new AuthScope(targetHost.getHostName(), targetHost.getPort()), new UsernamePasswordCredentials(username, password));

			// Create AuthCache instance
			AuthCache authCache = new BasicAuthCache();
			switch(authType.toUpperCase()){
				case "BASIC":	// Generate BASIC scheme object and add it to the local auth cache
								BasicScheme basicAuth = new BasicScheme();
								authCache.put(targetHost, basicAuth);
								break ;
				case "DIGEST": 	// Generate DIGEST scheme object, initialize it and add it to the local
					            // auth cache
					            DigestScheme digestAuth = new DigestScheme();
					            if(realm==null){
					            	realm = getRealmName(url, httpclient, targetHost, credsProvider, authCache) ;
					            }
					            
				            	// Suppose we already know the realm name
				            	digestAuth.overrideParamter("realm", realm);
				            	// Suppose we already know the expected nonce value
				            	digestAuth.overrideParamter("nonce", Long.toString(new Random().nextLong(), 36));
					           
					            authCache.put(targetHost, digestAuth);
					            break ;
				case "NTLM":
				//missing default case
        			default:
            			    // add default case
            				break;

			}
			
	
			// Add AuthCache to the execution context
			HttpClientContext context = HttpClientContext.create();
			context.setCredentialsProvider(credsProvider);
			context.setAuthCache(authCache);
	
			HttpGet httpget = new HttpGet(urlObj.getPath());
			

			ArrayList<String> authPrefs = new ArrayList<String>();
			authPrefs.add(AuthSchemes.NTLM);
			RequestConfig config = RequestConfig.custom().setProxyPreferredAuthSchemes(authPrefs).build();
			httpget.setConfig(config);
			
			response = httpclient.execute(targetHost, httpget, context);
			int code = response.getStatusLine().getStatusCode();
			if (code < 400) {
				return true ;
			}
			

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			if (response != null) {
				try {
					response.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return false;
	}
	





	private static String getRealmName(String url, CloseableHttpClient httpclient, HttpHost targetHost, CredentialsProvider credsProvider,
			AuthCache authCache) throws ClientProtocolException, IOException {
		HttpClientContext context = HttpClientContext.create();
		context.setCredentialsProvider(credsProvider);
		context.setAuthCache(authCache);

		HttpGet httpget = new HttpGet(url);
		CloseableHttpResponse response = httpclient.execute(targetHost, httpget, context);
		int code = response.getStatusLine().getStatusCode();
		if (code >= 400) {
			String[] values = response.getFirstHeader("Www-Authenticate").getValue().split(",") ;
			response.close();
			for(String val: values){
				if(val.contains("realm")){
					return val.split("=")[1] ;
				}
			}
		}
		
		return null;
		
	}

	
	public static boolean isNumeric(String str) {
		Pattern pattern = Pattern.compile("-?[0-9]*.?[0-9]*");
		Matcher isNum = pattern.matcher(str);
		if (!isNum.matches()) {
			return false;
		}
		return true;
	}

	public static void main(String[] args) {
//		System.out.println(validateConnection("BASIC", "http://httpbin.org/basic-auth/aaa/aaa", null, "aaa", "aaa"));
//		System.out.println(validateConnection("DIGEST" ,"http://httpbin.org/digest-auth/auth/user/passwd/MD5", null, "user", "passwd"));
		
//			System.out.println(NumberUtils.isNumber("993E-00121")) ;
			System.out.println(NumberUtils.isCreatable("0000789")) ;
			System.out.println(NumberUtils.isCreatable("0000456")) ;
//			System.out.println(NumberUtils.isNumber("0000000000000000000000000080270838")) ;
			
			
			
	}

}
