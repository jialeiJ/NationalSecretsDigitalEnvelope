package com.vienna.jaray.filter;

import org.apache.commons.lang3.StringEscapeUtils;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.nio.charset.Charset;
import java.util.*;

public class PostParamsRequestWrapper extends HttpServletRequestWrapper {

    private  byte[] body;
    String[] strArr = {"\"","%","'"};

    public PostParamsRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);

        //获取request域json类型参数
        String param = getBodyString(request);

        //拆分json，参数属性放一个List集合中
        List<String> shuxing = new ArrayList<String>();
        //拆分json，参数值放一个List集合中
        List<String> values = new ArrayList<String>();

        if(param!= null && !param.equals("")){
            String newParam = param.substring(1,param.length()-1);
            String[] arrParam = newParam.split(",");
            for(String arr : arrParam){
                String[] newArr =  arr.split(":");

                //属性
                String par = newArr[0].trim();
                if(par.contains("\"") && par.length()>2){
                    par = par.substring(1,par.length()-1);
                }
                shuxing.add(par);

                //值
                if(newArr.length>1){
                    String par1 = newArr[1].trim();
                    if(par1.contains("\"") && par1.length()>2){
                        par1 = par1.substring(1,par1.length()-1);
                    }
                    values.add(par1);
                }else{
                    values.add("");
                }
            }

            //对值里面的不合法参数转义
            for(int i = 0;i<shuxing.size();i++){
                for(String arr :strArr){
                    if(values.get(i).contains(arr)){
                        //对不合法参数values转义
                        String newValues = StringEscapeUtils.escapeXml(arr);
                        String s1 = values.get(i).replace(arr,newValues);
                        values.set(i,s1);
                    }
                }
            }
            StringBuffer bf =new StringBuffer();
            //重组json字符串
            for(int k = 0;k<shuxing.size();k++){
                if(k+1 != shuxing.size()){
                    bf.append("\""+shuxing.get(k)+"\""+":"+ "\""+ values.get(k)+"\""+",");
                }else{
                    bf.append("\""+shuxing.get(k)+"\""+":"+  "\""+values.get(k)+"\"");
                }
            }
            String sb = "{"+ bf.toString() +"}";
            body = sb.getBytes(Charset.forName("UTF-8"));
        }
    }

    /**
     * 获取请求Body
     *
     * @param request
     * @return
     */
    public String getBodyString(final ServletRequest request) {
        StringBuilder sb = new StringBuilder();
        InputStream inputStream = null;
        BufferedReader reader = null;
        try {
            inputStream = cloneInputStream(request.getInputStream());
            reader = new BufferedReader(new InputStreamReader(inputStream, Charset.forName("UTF-8")));
            String line = "";
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (reader != null) {
                try {
                    reader.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return sb.toString();
    }

    /**
     * Description: 复制输入流</br>
     *
     * @param inputStream
     * @return</br>
     */
    public InputStream cloneInputStream(ServletInputStream inputStream) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        try {
            while ((len = inputStream.read(buffer)) > -1) {
                byteArrayOutputStream.write(buffer, 0, len);
            }
            byteArrayOutputStream.flush();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        InputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        return byteArrayInputStream;
    }
    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {

        final ByteArrayInputStream bais = new ByteArrayInputStream(body);

        return new ServletInputStream() {

            @Override
            public int read() throws IOException {
                return bais.read();
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return false;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }
        };
    }

    /**
     * 把处理后的参数放到body里面
     * @param body
     */
    public void setBody(byte[] body) {
        this.body = body;
    }

}
