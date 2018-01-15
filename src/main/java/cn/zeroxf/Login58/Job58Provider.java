package cn.zeroxf.Login58;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpCookie;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

public class Job58Provider {
	private static final Logger logger = Logger.getLogger( Job58Provider.class.getName() );
	private String FRONTEND_URL = "http://passport.58.com/frontend/data?";
	private String TOKENCODE_URL = "http://passport.58.com/mobile/getcode?";
	private String LOGIN_URL = "https://passport.58.com/mobile/pc/login?";
	private String FINGERPRINT = "421A592E9D98DC7C0711A36033A582E84360ED23C621CCE3_011";
	private String FIGNERPRINT2 = "zh-CN|24|1|4|1600_900|1600_860|-480|1|1|1|undefined|undefined|"
			+ "unknown|Win64|unspecified|1|false|false|false|true|false|"
			+ "0_true_true|d41d8cd98f00b204e9800998ecf8427F|b01de87fcefd32c68d348cd9d18b62d9";
	private String JQUERYSTR = "jQuery183025066063002634587_" + getNow();
	private long initTime = (new Date()).getTime();
	private String TOKENCODE = "";
	private String TOKEN = "";

	protected CookieStore cookieStore = new BasicCookieStore();

	public void setCookieStore(HttpResponse httpResponse) {

		Header[] headers = httpResponse.getHeaders("Set-Cookie");
		if (headers != null && headers.length > 0) {
			for (int i = 0; i < headers.length; i++) {
				String setCookie = headers[i].getValue();
				try {
					BasicClientCookie cookie = this.parseRawCookie(setCookie);
					if (!cookie.isExpired(new Date())) {
						this.cookieStore.addCookie(cookie);
					}
				} catch (Exception e) {
					// do nothing
				}
			}
		}
		this.cookieStore.clearExpired(new Date());
	}


	protected BasicClientCookie parseRawCookie(String rawCookie) throws Exception {
		List<HttpCookie> cookies = HttpCookie.parse(rawCookie);
		if (cookies.size() < 1)
			return null;
		HttpCookie httpCookie = cookies.get(0);
		BasicClientCookie cookie = new BasicClientCookie(httpCookie.getName(), httpCookie.getValue());
		if (httpCookie.getMaxAge() >= 0) {
			Date expiryDate = new Date(System.currentTimeMillis() + httpCookie.getMaxAge() * 1000);
			cookie.setExpiryDate(expiryDate);
		}
		if (httpCookie.getDomain() != null)
			cookie.setDomain(httpCookie.getDomain());
		if (httpCookie.getPath() != null)
			cookie.setPath(httpCookie.getPath());
		if (httpCookie.getComment() != null)
			cookie.setComment(httpCookie.getComment());
		cookie.setSecure(httpCookie.getSecure());
		return cookie;
	}

	public String getCookieValue(String name) {
		if (this.cookieStore != null && this.cookieStore.getCookies() != null) {
			for (Cookie cookie : this.cookieStore.getCookies()) {
				if (cookie.getName().equalsIgnoreCase(name)) {
					return cookie.getValue();
				}
			}
		}
		return null;
	}


	protected CloseableHttpClient createHttpClient() {

		HttpClientBuilder httpClientBuilder = HttpClients.custom().useSystemProperties()
				.setDefaultCookieStore(cookieStore);
		SSLContext sslContext;
		try {
			sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
				public boolean isTrusted(X509Certificate[] chain, String authType) {
					return true;
				}
			}).build();
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
			httpClientBuilder.setSSLSocketFactory(sslsf);
			httpClientBuilder.setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
			//
		}
		return httpClientBuilder.build();
	}

	private String getJQueryCallBackStr() {
		return "callback=" + JQUERYSTR + "&_=" + getNow();
	}

	public String doGet(String url, String host) throws Exception {
		CloseableHttpClient client = this.createHttpClient();
		HttpGet get = new HttpGet(url);
		get.addHeader("Connection", "keep-alive");
		get.addHeader("accept",
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8");
		get.addHeader("accept-encoding", "gzip, deflate, br");
		get.addHeader("accept-language", "en-US,en;q=0.9");
		get.addHeader("upgrade-insecure-requests", "1");
		get.addHeader("user-agent",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36");
		get.addHeader("Host", host);
		CloseableHttpResponse response = client.execute(get);
		if (response == null) {
			throw new Exception("network error, unable to connect to 51job");
		}
		setCookieStore(response);
		HttpEntity entity = response.getEntity();
		InputStream stream = entity.getContent();
		String result = IOUtils.toString(stream, "utf-8");

		IOUtils.closeQuietly(stream);
		EntityUtils.consumeQuietly(entity);
		HttpClientUtils.closeQuietly(client);
		return result;
	}

	protected String encryptStr(String str) {
		Long timeSpan = 1411093327735L;
		Long randomLong = timeSpan + (new Date()).getTime() - initTime;
		String timeSign = String.valueOf(randomLong);
		String passwd = timeSign + str;
		String encryptPwd = QuanzhouJSUtil.getEncryptString(passwd);
		return encryptPwd;
	}

	protected String getNow() {
		Date date = new Date();
		return String.valueOf(date.getTime());
	}

	protected String getResponseParameter(InputStream stream, String parameterName) {
		String response = "";
		try {
			response = IOUtils.toString(stream, "utf-8");
		} catch (IOException e) {
			e.printStackTrace();
		}
		return getResponseParameter(response, parameterName);
	}

	protected String getResponseParameter(String response, String parameterName) {
		String result = response.replaceAll(",|\"|:", " ");
		StringTokenizer tokenizer = new StringTokenizer(result, " ");
		while (tokenizer.hasMoreTokens() && !tokenizer.nextToken().equals(parameterName)) {
		}
		String token = tokenizer.nextToken();
		return token;
	}

	private void loginJob58(String phoneNumber, String mobileCode) throws Exception {
		String enPhone = encryptStr(phoneNumber);
		String fingerPrint2 = URLEncoder.encode(FIGNERPRINT2, "utf-8");
		String loginURL = LOGIN_URL + "mobile=" + enPhone + "&mobilecode=" + mobileCode + "&source=" + "pc-login"
				+ "&token=" + TOKEN + "&tokencode=" + TOKENCODE + "&fingerprint=" + FINGERPRINT + "&isremember="
				+ "false" + "&finger2=" + fingerPrint2 + "&path=" + "";
		String result = doGet(loginURL, "passport.58.com");
	
		String code = getResponseParameter(result, "code");
		logger.info(result);
		if (!code.equals("0")) {
			throw new Exception("登录失败");
		}

	}

	public void preLogin() {
		cookieStore.clear();
		initTime = (new Date()).getTime();

	}

	public void getPhoneCode(String phoneNumber) throws Exception {

		// 获得token,然后用token作为参数获取tokenCode, 然后发送验证码登录时候需要用到tokenCode和token
		String result = doGet(FRONTEND_URL + getJQueryCallBackStr(), "passport.58.com");
		TOKEN = getResponseParameter(result, "token");

		// 获取token code
		String enPhone = encryptStr(phoneNumber);
		String tokenCodeURL = TOKENCODE_URL + "mobile=" + enPhone + "&validcode=&source=pc-login&vcodekey=&token="
				+ TOKEN + "&voicetype=0&codetype=0&fingerprint=" + FINGERPRINT + "&" + getJQueryCallBackStr() + "&path="
				+ "http://my.58.com";
		result = doGet(tokenCodeURL, "passport.58.com");
		TOKENCODE = getResponseParameter(result, "tokencode");

	}
	
	@Test
	public void testLogin58(){
		preLogin();
		String phoneNum = "";
		String mobileCode = "";
		System.out.println("请输入你的手机号码:");
		Scanner scanner = new Scanner(System.in);
		phoneNum = scanner.nextLine();
		try {
			getPhoneCode(phoneNum);
			System.out.println("请输入你的手机验证码:");
			mobileCode = scanner.nextLine();
			loginJob58(phoneNum, mobileCode);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//add some code to do
		
		
		scanner.close();
		
	}

}
