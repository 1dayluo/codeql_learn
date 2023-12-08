/**
 * @name XXEE Detect
 * @description 参考：https://shu1l.github.io/2021/01/27/java-dai-ma-shen-ji-zhi-chang-jian-lou-dong-xue-xi/
 *          写的一个xxe查询codeql脚本～
 *              
 * @kind 
 * @problem.severity error
 * @security-severity 7.1
 * @precision high
 * @id java/xss
 * @tags security
 *       xxe detect
 */

 import java

 predicate searchXMLClass(Class c) {
     c.getASubtype*().hasQualifiedName("javax.xml.parsers", "DocumentBuilder") or 
     c.getASubtype*().hasQualifiedName("javax.xml.stream", "XMLStreamReader") or 
     c.getASubtype*().hasQualifiedName("jdom.input", "SAXBuilder") or 
     c.getASubtype*().hasQualifiedName("jdom2.input", "SAXBuilder") or 
     c.getASubtype*().hasQualifiedName("javax.xml.parsers", "SAXParser") or 
     c.getASubtype*().hasQualifiedName("org.dom4j.io", "SAXReader") or 
     c.getASubtype*().hasQualifiedName("org.xml.sax", "XMLReader") or 
     c.getASubtype*().hasQualifiedName("javax.xml.transform.sax", "SAXParser") or 
     c.getASubtype*().hasQualifiedName("javax.xml.transform", "TransformerFactory") or 
     c.getASubtype*().hasQualifiedName("xml.transform.sax", "SAXTransformerFactory") or 
     c.getASubtype*().hasQualifiedName("xml.validation", "SchemaFactory") or 
     c.getASubtype*().hasQualifiedName("javax.xml.bind", "Unmarshaller") or 
     c.getASubtype*().hasQualifiedName("javax.xml.xpath", "XPathEx")
 }
 
 from Class c, Field f
  where searchXMLClass(c) and
  f.getDeclaringType() = c and 
  f.getAModifier().getName() = "public"
  select  c.getQualifiedName(),f.getName()