package com.vienna.jaray.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.vienna.jaray.constant.ErrorCode;
import com.vienna.jaray.model.ApiResponse;
import com.vienna.jaray.utils.ParsePackageParamsUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;


/**
 * 国密数字信封(SM2、SM3、SM4)，校验签名、解密过滤器
 */
@Slf4j
@Order(1)   // 优先执行
@WebFilter
public class NationalSecretsVerifySignFilter implements Filter {

    private static final String MOTHOD_POST = "POST";
    private static final String MOTHOD_GET = "GET";

    @Autowired
    private ParsePackageParamsUtil parsePackageParamsUtil;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        TreeMap paramsMaps = new TreeMap();
        HttpServletResponse resp = (HttpServletResponse) response;

        //获取访问 ip 地址
        String visitIp = req.getRemoteAddr();
        visitIp = "0:0:0:0:0:0:0:1".equals(visitIp) ? "127.0.0.1" : visitIp;
        // 每次拦截到请求输出访问 ip
        log.debug("国密数字信封过滤器 访问 IP = {}  url = {}", visitIp, req.getRequestURL());

        String method = req.getMethod();

        ResponseWrapper responseWrapper = new ResponseWrapper((HttpServletResponse) response);
        String url = req.getRequestURL().toString();
        // 用来区分国密与非国密
        boolean contain = url.contains("nationalSecrets");

        /**
         * 获取请求参数
         */
        if (StringUtils.equalsIgnoreCase(MOTHOD_POST, method) && contain) {
            // 防止流读取一次后就没有了, 所以需要将流继续写出去
            PostParamsRequestWrapper requestWrapper = new PostParamsRequestWrapper(req);
            ServletInputStream inputStream = requestWrapper.getInputStream();
            InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            BufferedReader bfReader = new BufferedReader(reader);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = bfReader.readLine()) != null){
                sb.append(line);
            }

            String body = sb.toString();
            paramsMaps = JSONObject.parseObject(body, TreeMap.class);
            log.debug("国密数字信封过滤器 post请求 parameterMap：{}", JSONObject.toJSONString(paramsMaps));

            boolean verifyResult = parsePackageParamsUtil.VerifyDataLegalityForNationalSecrets(paramsMaps.get("ciphertext").toString(), paramsMaps.get("key").toString(), paramsMaps.get("iv").toString(), paramsMaps.get("hash").toString(), paramsMaps.get("sign").toString());

            log.debug("国密数字信封过滤器 post请求 verifyResult：{}",  verifyResult);
            if (!verifyResult) {
                ApiResponse apiResponse = new ApiResponse();
                apiResponse.setErrorCode(ErrorCode.ILLEGAL_DATA.getStatusCodeStr());
                apiResponse.setErrorMsg(ErrorCode.ILLEGAL_DATA.getStatusDesc());
                returnJson(resp, JSON.toJSONString(apiResponse));
                return;
            } else {
                String jsonBodyStr = parsePackageParamsUtil.parseFrontDataForNationalSecrets(paramsMaps.get("ciphertext").toString(), paramsMaps.get("key").toString(), paramsMaps.get("iv").toString());
                log.debug("国密数字信封过滤器 post请求 解密后的body字符串：{}",  jsonBodyStr);
                requestWrapper.setBody(jsonBodyStr.getBytes("UTF-8"));
                chain.doFilter(requestWrapper, responseWrapper);
            }

        } else if (StringUtils.equalsIgnoreCase(MOTHOD_GET, method) && contain) {
            GetParamsRequestWrapper requestWrapper = new GetParamsRequestWrapper(req);
            Map<String, String[]> parameterMap = requestWrapper.getParameterMap();
            Set<Map.Entry<String, String[]>> entries = parameterMap.entrySet();
            Iterator<Map.Entry<String, String[]>> iterator = entries.iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, String[]> next = iterator.next();
                paramsMaps.put(next.getKey(), next.getValue()[0]);
            }
            log.debug("国密数字信封过滤器 get请求 parameterMap: {}", JSONObject.toJSONString(paramsMaps));

            boolean verifyResult = parsePackageParamsUtil.VerifyDataLegalityForNationalSecrets(paramsMaps.get("ciphertext").toString(), paramsMaps.get("key").toString(), paramsMaps.get("iv").toString(), paramsMaps.get("hash").toString(), paramsMaps.get("sign").toString());

            log.debug("国密数字信封过滤器 get请求 verifyResult：{}", verifyResult);
            if (!verifyResult) {
                ApiResponse apiResponse = new ApiResponse();
                apiResponse.setErrorCode(ErrorCode.ILLEGAL_DATA.getStatusCodeStr());
                apiResponse.setErrorMsg(ErrorCode.ILLEGAL_DATA.getStatusDesc());
                returnJson(resp, JSON.toJSONString(apiResponse));
                return;
            } else {
                String jsonBodyStr = parsePackageParamsUtil.parseFrontDataForNationalSecrets(paramsMaps.get("ciphertext").toString(), paramsMaps.get("key").toString(), paramsMaps.get("iv").toString());
                log.debug("国密数字信封过滤器 get请求 解密后的body字符串：{}",  jsonBodyStr);
                paramsMaps = JSONObject.parseObject(jsonBodyStr, TreeMap.class);
                requestWrapper.setParameters(paramsMaps);
                requestWrapper.addParameter("userName", "李四");
                chain.doFilter(requestWrapper, responseWrapper);
            }
        } else {
            chain.doFilter(request, response);
        }

        if (contain) {
            byte[] content = responseWrapper.getContent();
            String responseStr = new String(content, "UTF-8");
            responseStr = parsePackageParamsUtil.packageResponseDataForNationalSecrets(responseStr);

            //把返回值输出到客户端
            ServletOutputStream out = response.getOutputStream();
            byte[] re = responseStr.getBytes("UTF-8");
            response.setContentLength(re.length);//重新设置返回长度
            out.write(re);
        }
    }


    private void returnJson(HttpServletResponse response, String json) {
        PrintWriter pw = null;
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.addHeader("Access-Control-Allow-Origin","*");
        try {
            pw = response.getWriter();
            pw.print(json);
        } catch (IOException e) {
            log.error("响应返回异常：{}", e);
        } finally {
            if (pw != null)
                pw.close();
        }
    }
}
