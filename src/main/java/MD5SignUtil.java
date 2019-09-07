import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;

import java.beans.PropertyDescriptor;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author kunma
 * @date 2017/11/5*/


public class MD5SignUtil {

/**
     * 获取sign 入参为dto
     *
     * @param object
     * @param key
     * @return*/


    public static String sign(Object object, String key) {
        String sign = null;
        Map<String, Object> map = convertObjectToMap(object);
        String mapstr = getSignDataIgnoreNullObject(map);
        sign = sign(mapstr, key);
        return sign;
    }
/*
*
     * 获取sign 入参为map
     *
     * @param map
     * @param key
     * @return*/


    public static String sign(Map<String, Object> map, String key) {
        String sign = null;
        String mapstr = getSignDataIgnoreNullObject(map);
        sign = sign(mapstr, key);
        return sign;
    }

/*
*
     * 验签
     *
     * @param obj  入参dto
     * @param key  签名key
     * @param sign 入参签名
     * @return
*/


    public static boolean verifySign(Object obj, String key, String sign) {
        String objSign = sign(obj, key);
        return sign.equals(objSign);
    }

/*
*
     * 验签
     *
     * @param map  入参dto
     * @param key  签名key
     * @param sign 入参签名
     * @return
*/


    public static boolean verifySign(Map<String, Object> map, String sign, String key) {
        String objSign = sign(getSignDataIgnoreNullObject(map), key);
        return sign.equals(objSign);
    }

/**
     * 生成签名
     *
     * @param content
     * @param key
     * @return
     * @throws Exception*/


    public static String sign(String content, String key) {
        String sign = null;
        try {
            sign = sign(content, key, "utf-8");
        } catch (Exception e) {

        }
        return sign;
    }

    public static String sign(String content, String key, String charset) throws Exception {

        String tosign = (content == null ? "" : content) + key;

        try {
            return DigestUtils.md5Hex(getContentBytes(tosign, charset));
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(" MD5 Exception [content = " + content + "; charset = utf-8" + "]Exception!",
                    e);
        }
    }

/**
     * 取正常md5(32位)的前30位
     *
     * @param content
     * @param key
     * @return
     * @throws Exception*/


    public static String signFor19bit(String content, String key) throws Exception {
        String signString = sign(content, key);
        signString = signString.substring(0, 19);
        return signString;

    }

/**
     * 财付通网银验签时，要求验签的字符集和返回参数的字符集一样，所以加了一个charset
     *
     * @param content
     * @param charset
     * @return
     * @throws Exception*/


    public static String md5Direct(String content, String charset) throws Exception {
        try {
            return DigestUtils.md5Hex(getContentBytes(content, charset));
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(" MD5 Exception [content = " + content + "; charset = utf-8" + "]Exception!",
                    e);
        }
    }

    public static String md5Direct(String content) throws Exception {
        try {
            return DigestUtils.md5Hex(getContentBytes(content, "utf-8"));
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(" MD5 Exception [content = " + content + "; charset = utf-8" + "]Exception!",
                    e);
        }
    }

/**
     * 验证签名
     *
     * @param content
     * @param sign
     * @param key
     * @return
     * @throws Exception*/


    public static boolean verify(String content, String sign, String key) throws Exception {
        return verify(content, sign, key, "utf-8");
    }

/**
     * 对30位的md5值进行验签
     *
     * @param content
     * @param sign
     * @param key
     * @return
     * @throws Exception*/


    public static boolean verifyFor19Bit(String content, String sign, String key) throws Exception {
        String tosign = (content == null ? "" : content) + key;
        try {
            String mySign = DigestUtils.md5Hex(getContentBytes(tosign, "utf-8"));
            mySign = mySign.substring(0, 19);
            return StringUtils.equals(mySign, sign) ? true : false;
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException("MD5Exception[content = " + content + "; charset =" + "utf-8"
                    + "; signature = " + sign + "]Exception!", e);
        }
    }

    public static boolean verify(String content, String sign, String key, String charset) throws Exception {
        String tosign = (content == null ? "" : content) + key;
        try {
            String mySign = DigestUtils.md5Hex(getContentBytes(tosign, charset));

            return StringUtils.equals(mySign, sign) ? true : false;
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException("MD5Exception[content = " + content + "; charset =" + charset
                    + "; signature = " + sign + "]Exception!", e);
        }
    }

/**
     * @param content
     * @param charset
     * @return
     * @throws SignatureException
     * @throws UnsupportedEncodingException*/


    protected static byte[] getContentBytes(String content, String charset) throws UnsupportedEncodingException {
        if (StringUtils.isEmpty(charset)) {
            return content.getBytes();
        }
        return content.getBytes(charset);
    }

    public static int avg(int d, long m) {
        return d / (int) m;
    }

/*
*
     * 将Map组装成待签名数据。 待签名的数据必须按照一定的顺序排列 这个是支付宝提供的服务的规范，否则调用支付宝的服务会通不过签名验证
     *
     * @param params
     * @return
*/


    public static String getSignData(Map<String, String> params) {
        StringBuffer content = new StringBuffer();

        // 按照key做排序
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);

        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);
            if ("sign".equals(key) || "sign_type".equals(key) || "tuangou_extend".equals(key)) {
                continue;
            }
            String value = (String) params.get(key);
            if (value != null) {
                content.append((i == 0 ? "" : "&") + key + "=" + value);
            } else {
                content.append((i == 0 ? "" : "&") + key + "=");
            }
        }

        return content.toString();
    }

/*
*
     * 将Map组装成待签名数据。 待签名的数据必须按照一定的顺序排列 这个是支付宝提供的服务的规范，否则调用支付宝的服务会通不过签名验证
     *
     * @param params
     * @return
*/


    public static String getSignDataObject(Map<String, Object> params) {
        StringBuffer content = new StringBuffer();

        // 按照key做排序
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);

        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);
            if ("sign".equals(key) || "sign_type".equals(key) || "tuangou_extend".equals(key)) {
                continue;
            }
            String value = (String) params.get(key);
            if (value != null) {
                content.append((i == 0 ? "" : "&") + key + "=" + value);
            } else {
                content.append((i == 0 ? "" : "&") + key + "=");
            }
        }

        return content.toString();
    }

/*
*
     * 组装微信支付请求签名串,要求key排序小写
     *
     * @param params
     * @return
*/


    public static String getSignDataLowerCaseKeyIgnoreNull(Map<String, String> params) {
        StringBuffer content = new StringBuffer();

        // 按照key做排序
        List<String> keys = new ArrayList<String>(params.keySet());
        Comparator<String> comp = new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                return s1.toLowerCase().compareTo(s2.toLowerCase());
            }
        };
        Collections.sort(keys, comp);
        int count = 0;
        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);
            if ("paySign".equals(key) || "sign".equals(key) || "app_signature".equals(key) || "sign_method".equals(key)) {
                continue;
            }
            String value = (String) params.get(key);
            if (value != null && !"".equals(value)) {
                content.append((count == 0 ? "" : "&") + key.toLowerCase() + "=" + value);
                count++;
            }
        }

        return content.toString();
    }

/**
     * 忽略掉Null的值。
     *
     * @param params
     * @return*/


    public static String getSignDataIgnoreNull(Map<String, String> params) {
        StringBuffer content = new StringBuffer();

        // 按照key做排序
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);
        int count = 0;
        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);
            // sign_type计入微信签名串,后续更改请注意！
            if ("sign".equals(key) || "sign_method".equals(key)) {
                continue;
            }
            String value = (String) params.get(key);
            if (value != null && !"".equals(value)) {
                content.append((count == 0 ? "" : "&") + key + "=" + value);
                count++;
            }
        }

        return content.toString();
    }

/*
*
     * 忽略掉Null的值。
     *
     * @param params
     * @return
*/


    public static String getSignDataIgnoreNullObject(Map<String, Object> params) {
        StringBuilder content = new StringBuilder();

        // 按照key做排序
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);
        int count = 0;
        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);
            if ("sign".equals(key)) {
                continue;
            }
            if (params.get(key) != null) {
                String value = params.get(key).toString();
                if (StringUtils.isNotEmpty(value)) {
                    content.append((count == 0 ? "" : "&") + key + "=" + value);
                    count++;
                }
            }
        }

        return content.toString();
    }

/*
*
     * 忽略掉Null的值。
     *
     * @param params
     * @return
     * @throws UnsupportedEncodingException
*/


    public static String getSignDataIgnoreNullWithEncode(Map<String, String> params)
            throws UnsupportedEncodingException {
        StringBuffer content = new StringBuffer();

        // 按照key做排序
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);
        int count = 0;
        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);

            String value = (String) params.get(key);
            if (value != null && !"".equals(value)) {
                content.append((count == 0 ? "" : "&") + key + "=" + URLEncoder.encode(value, "utf-8"));
                count++;
            }
        }

        return content.toString();
    }

/**
     * 将Map中的数据组装成url
     *
     * @param params
     * @return
     * @throws UnsupportedEncodingException*/


    public static String mapToUrl(Map<String, String> params, boolean needSort) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        List<String> keys = new ArrayList<String>(params.keySet());
        if (needSort)
            Collections.sort(keys);
        for (int i = 0; i < keys.size(); i++) {
            String value = params.get(keys.get(i));
            if (i == 0) {
                sb.append(keys.get(i) + "=" + URLEncoder.encode(value, "utf-8"));
            } else {
                if (value != null) {
                    sb.append("&" + keys.get(i) + "=" + URLEncoder.encode(value, "utf-8"));
                } else {
                    sb.append("&" + keys.get(i) + "=");
                }
            }
        }
        return sb.toString();
    }

/**
     * 取得URL中的参数值。
     * <p>
     * 如不存在，返回空值。
     * </p>
     *
     * @param url
     * @param name
     * @return*/


    public static String getParameter(String url, String name) {
        if (name == null || name.equals("")) {
            return null;
        }
        name = name + "=";
        int start = url.indexOf(name);
        if (start < 0) {
            return null;
        }
        start += name.length();
        int end = url.indexOf("&", start);
        if (end == -1) {
            end = url.length();
        }
        return url.substring(start, end);
    }

    // 得到xml字符串节点内容
    public static String getXmlValue(String xml, String name) {
        if (StringUtils.isBlank(xml) || StringUtils.isBlank(name)) {
            return "";
        }
        int start = xml.indexOf("<" + name + ">");
        start += (name.length() + 2);// 去掉本字符串和"<"、">"的长度
        int end = xml.indexOf("</" + name + ">");
        if (end > start && end <= (xml.length() - name.length() - 2)) {
            return xml.substring(start, end);
        } else {
            return "";
        }
    }

    public static String getXmlValueNull(String xml, String name) {
        if (StringUtils.isBlank(xml) || StringUtils.isBlank(name)) {
            return "";
        }
        int start = xml.indexOf("<" + name + ">");
        start += (name.length() + 2);// 去掉本字符串和"<"、">"的长度
        int end = xml.indexOf("</" + name + ">");
        if (end > start && end <= (xml.length() - name.length() - 2)) {
            return xml.substring(start, end);
        } else {
            return null;
        }
    }

/*
*
     * 微信转码将空格转为%20而不是+
     *
     * @param param
     * @return
*/


    public static Map<String, String> urlEncode4WeiXin(Map<String, String> param) {
        Map<String, String> p = new HashMap<String, String>();
        try {
            if (param == null || param.isEmpty()) {
                return p;
            }
            for (String key : param.keySet()) {
                p.put(key, URLEncoder.encode(param.get(key), "UTF-8").replaceAll("\\+", "%20"));
            }
            return p;
        } catch (Exception e) {
            return p;
        }
    }

    public static Map<String, String> urlEncode(Map<String, String> param) {
        Map<String, String> p = new HashMap<String, String>();
        try {
            if (param == null || param.isEmpty()) {
                return p;
            }
            for (String key : param.keySet()) {
                p.put(key, encodeURIComponent(param.get(key)));
            }
            return p;
        } catch (Exception e) {
            return p;
        }
    }

    public static String encodeURIComponent(String component) {
        String result = null;
        try {
            result = URLEncoder.encode(component, "UTF-8").replaceAll("\\%28", "(").replaceAll("\\%29", ")")
                    .replaceAll("\\%20", "+").replaceAll("\\%27", "'").replaceAll("\\%21", "!")
                    .replaceAll("\\%7E", "~");
        } catch (UnsupportedEncodingException e) {
            result = component;
        }
        return result;
    }

    public static String getSignData4UnionEBank(Map<String, String> params) {
        StringBuffer content = new StringBuffer();

        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);

        for (int i = 0; i < keys.size(); i++) {
            String key = (String) keys.get(i);
            if ((!"signMethod".equals(key)) && (!"signature".equals(key))) {
                String value = (String) params.get(key);
                if (value != null)
                    content.append((i == 0 ? "" : "&") + key + "=" + value);
                else {
                    content.append((i == 0 ? "" : "&") + key + "=");
                }
            }
        }
        return content.toString();
    }

/*
*
     * dto转成map
     *
     * @param obj
     * @return
*/


    public static Map<String, Object> convertObjectToMap(Object obj) {
        Map<String, Object> hashMap = new HashMap<String, Object>();
        if (null == obj) {
            return null;
        }
        @SuppressWarnings("rawtypes")
        Class cls = obj.getClass();
        Field[] fields = cls.getDeclaredFields();

        if (null == fields) {
            return null;
        }
        for (Field field : fields) {
            PropertyDescriptor pd;
            try {
                String name = field.getName();
                pd = new PropertyDescriptor(field.getName(), cls);
                Method readMethod = pd.getReadMethod();
                String value = String.valueOf(readMethod.invoke(obj));
                if (!"null".equals(value) || "sign".equals(name)) {
                    hashMap.put(name, value);
                }
            } catch (Exception e) {
                return null;
            }
        }
        return hashMap;
    }
}
