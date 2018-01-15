package cn.zeroxf.Login58;

import java.io.InputStream;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

public class QuanzhouJSUtil {
	
	private static final Logger logger = LoggerFactory.getLogger(QuanzhouJSUtil.class);

	
	private static ScriptEngine rsaCodeEngine;
	

	static {
		
		ClassPathResource rsaCodeJs = new ClassPathResource("js/Rsa.js");
		InputStream rsaCodeIs = null;
		try {
			rsaCodeIs = rsaCodeJs.getInputStream();
			String rsaCode = IOUtils.toString(rsaCodeIs, "utf-8");
			rsaCodeEngine = new ScriptEngineManager().getEngineByName("javascript");
			rsaCodeEngine.eval(rsaCode);

		} catch (Exception e) {
			logger.error("execute javascript engine failed with " + e.getMessage());
		} finally {
			IOUtils.closeQuietly(rsaCodeIs);
		}

	}
	public static String getEncryptString(String pwd) {
		Object result = "";
		try {
			result = ((Invocable)rsaCodeEngine).invokeFunction("encryptString", pwd);
		} catch (NoSuchMethodException | ScriptException e) {
		}
		return String.valueOf(result);
		
	}

}
