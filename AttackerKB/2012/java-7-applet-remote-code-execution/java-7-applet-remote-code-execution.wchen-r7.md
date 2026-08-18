---
title: Java 7 Applet Remote Code Execution
author: wchen-r7
score: 2
topic_attacker_value: 5
topic_exploitability: 1
topic_disclosure_date: '2012-08-28T00:55:00'
created: '2019-09-12T18:07:55.18032'
revision_date: '2020-02-13T17:12:08.009205'
assessment_id: cc59810c-072d-42d0-b0e4-b15204ff53f3
topic_id: 45c06f42-ee61-4551-8298-0b856111798f
topic_short_id: 1Myr12AaoJ
topic_slug: java-7-applet-remote-code-execution
akb_topic_url: https://attackerkb.com/topics/1Myr12AaoJ/java-7-applet-remote-code-execution
akb_assessment_url: https://attackerkb.com/topics/1Myr12AaoJ/java-7-applet-remote-code-execution#cc59810c-072d-42d0-b0e4-b15204ff53f3
---

# Java 7 Applet Remote Code Execution

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/1Myr12AaoJ/java-7-applet-remote-code-execution#cc59810c-072d-42d0-b0e4-b15204ff53f3).*

---

# References

References about the attack:

* http://labs.alienvault.com/labs/index.php/2012/new-java-0day-exploited-in-the-wild/
* http://blog.fireeye.com/research/2012/08/zero-day-season-is-not-over-yet.html
* http://www.deependresearch.org/2012/08/java-7-vulnerability-analysis.html
* http://eromang.zataz.com/2012/08/27/oracle-java-0day-and-the-myth-of-a-targeted-attack/
* http://scrammed.blogspot.com/2012/08/analysing-cve-2012-xxxx-latest-java-0day.html
* http://www.us-cert.gov/cas/techalerts/TA12-240A.html
* http://www.kahusecurity.com/2012/java-0-day-using-latest-dadongs-js-obfuscator/
* http://thexploit.com/sec/java-facepalm-suntoolkit-getfield-vulnerability/
* http://immunityproducts.blogspot.com.ar/2012/08/java-0day-analysis-cve-2012-4681.html
* http://www.guardian.co.uk/technology/2012/aug/30/java-exploit-asian-hackers-says-symantec?newsfeed=true

References about the Java API used:

* http://www.docjar.com/html/api/java/beans/Statement.java.html     // See ClassFinder & findMethod
* http://www.docjar.com/html/api/sun/awt/SunToolkit.java.html       // See getField()
* http://docs.oracle.com/javase/7/docs/api/overview-summary.html
* http://www.oracle.com/technetwork/java/seccodeguide-139067.html


getField() wasn't always public, see the following for an example:

http://javasourcecode.org/html/open-source/jdk/jdk-6u23/sun/awt/SunToolkit.java.html

# Summary

This is a vulnerability specifically targeting Java 7.  Some reports reveal the origin of the 0day
exploit comes from a popular exploit kit named "Gondad Exploit Kit" (google "ZZVnxA1X"), some people
also claim the 0day originally comes from VulnDisco, which is an exploit pack used by Immunity
Canvas.  No matter, the public noticed the attack as a malware being hosted at 59.120.154.62, which
is a server located in Taiwan.  The decompiled source also has strings (lyrics) such as
"woyouyizhixiaomaolv" and "conglaiyebuqi" indicating that whoever wrote it must know Mandarin Chinese
quite well, possibly China because that's "Pinyin" input method, and he probably grew up there
due the choice of the song.  It would be reasonable to say that someone in China has been using the
exploit, and hosts the malicious code on a compromised server in Taiwan.

The actual link to the live exploit is:
hxxp://59.120.154.62/meeting/index.html

The exploit takes advantage of two issues: The ClassFinder and MethodFinder.findMethod().  Both
were newly introduced in JDK 7.  ClassFinder is a replacement for classForName back in JDK 6. It
allows untrusted code to obtain a reference and have access to a restricted package in JDK 7, which
can be used to abuse sun.awt.SunToolkit (a restricted package).  With sun.awt.SunToolkit, we can
actually invoke getField() by abusing findMethod() in Statement.invokeInternal() (but getField()
must be public, and that's not always the case in JDK 6) in order to access Statement.acc's private
field, modify AccessControlContext, and then disable Security Manager. Once Security Manager is
disabled, we can execute arbitrary Java code.

Our exploit has been tested successfully against multiple platforms, including: IE, Firefox, Safari,
Chrome; Windows, Ubuntu, OS X, etc.  We have even received reports claiming the exploit also works
against Solaris.

# Timeline

Aug xx 2011 - Vulnerable code was introduced in JDK7
Apr xx 2012 - Oracle already aware of the vulnerabilities:  http://www.theregister.co.uk/2012/08/30/oracle_knew_about_flaws/
Jun xx 2012 - Infected server hosting malware code: http://urlquery.net/report.php?id=70896
Aug 26 2012 - First blog emerged about the Java 0day: http://blog.fireeye.com/research/2012/08/zero-day-season-is-not-over-yet.html
Aug 26 2012 - PoC extracted from the malicious site by Joshua Drake: https://twitter.com/jduck1337/status/239875285913317376
Aug 27 2012 - Metasploit exploit available: https://community.rapid7.com/community/metasploit/blog/2012/08/27/lets-start-the-week-with-a-new-java-0day
Aug 28 2012 - CVE assigned as CVE-2012-4681
Aug 30 2012 - Java 7 Update 7 available (out of band patch)

Exceptions happens on this line of the Exploit:

```
GetClass("sun.awt.SunToolkit")

    private Class GetClass(String paramString)
        throws Throwable
    {
        Object arrayOfObject[] = new Object[1];
        arrayOfObject[0] = paramString;
        Expression localExpression = new Expression(Class.class, "forName", arrayOfObject); <===
        localExpression.execute(); // (3) Fails !!! <====
        return (Class)localExpression.getValue();
    }
```

Through Expression it tries to do Class.forName("sun.awt.SunToolkit"). Despite the use of
Expression, according to the Exception on Java6 root cause seems to be on Class.forName.

When checking java 7 api you can read:

```
public static Class classForName(String name) throws ClassNotFoundException
Deprecated! As - of JDK version 7, replaced by ClassFinder#resolveClass(String) .
```

Returns the Class object associated with the class or interface with the given string name, using the default class loader

So maybe something was lost con ClassFinder#resolveClass....


Digging into source code of openjdk:

* On Java 7
     ======

```
jdk/src/share/classes/java/lang/Class.java

    public static Class<?> forName(String className)
                throws ClassNotFoundException {
        return forName0(className, true, ClassLoader.getCallerClassLoader());
    }


    /** Called after security checks have been made. */
    private static native Class<?> forName0(String name, boolean initialize,
                                            ClassLoader loader)
        throws ClassNotFoundException;


jdk/src/share/native/java/lang/Class.c

JNIEXPORT jclass JNICALL
Java_java_lang_Class_forName0(JNIEnv *env, jclass this, jstring classname,
                              jboolean initialize, jobject loader)

....
    cls = JVM_FindClassFromClassLoader(env, clname, initialize,
                                       loader, JNI_FALSE);
```



hotspot/src/share/vm/prims/jvm.cpp

```
JVM_ENTRY(jclass, JVM_FindClassFromClassLoader(JNIEnv* env, const char* name,
                                               jboolean init, jobject loader,
                                               jboolean throwError))
  JVMWrapper3("JVM_FindClassFromClassLoader %s throw %s", name,
               throwError ? "error" : "exception");
  // Java libraries should ensure that name is never null...
  if (name == NULL || (int)strlen(name) > Symbol::max_length()) {
    // It's impossible to create this class;  the name cannot fit
    // into the constant pool.
    if (throwError) {
      THROW_MSG_0(vmSymbols::java_lang_NoClassDefFoundError(), name);
    } else {
      THROW_MSG_0(vmSymbols::java_lang_ClassNotFoundException(), name);
    }
  }
  TempNewSymbol h_name = SymbolTable::new_symbol(name, CHECK_NULL);
  Handle h_loader(THREAD, JNIHandles::resolve(loader));
  jclass result = find_class_from_class_loader(env, h_name, init, h_loader,
                                               Handle(), throwError, THREAD);

  if (TraceClassResolution && result != NULL) {
    trace_class_resolution(java_lang_Class::as_klassOop(JNIHandles::resolve_non_null(result)));
  }
  return result;
JVM_END
```

hotspot/src/share/vm/classfile/systemDictionary.cpp

```
jclass find_class_from_class_loader(JNIEnv* env, symbolHandle name, jboolean init, Handle loader, Handle protection_domain, jboolean throwError, TRAPS) {
  // Security Note:
  //   The Java level wrapper will perform the necessary security check allowing
  //   us to pass the NULL as the initiating class loader.
  klassOop klass = SystemDictionary::resolve_or_fail(name, loader, protection_domain, throwError != 0, CHECK_NULL);

  KlassHandle klass_handle(THREAD, klass);
  // Check if we should initialize the class
  if (init && klass_handle->oop_is_instance()) {
    klass_handle->initialize(CHECK_NULL);
  }
  return (jclass) JNIHandles::make_local(env, klass_handle->java_mirror());
}

hotspot/src/share/vm/classfile/systemDictionary.cpp

klassOop SystemDictionary::resolve_or_fail(symbolHandle class_name, Handle class_loader, Handle protection_domain, bool throw_error, TRAPS) {
  klassOop klass = resolve_or_null(class_name, class_loader, protection_domain, THREAD);
  if (HAS_PENDING_EXCEPTION || klass == NULL) {
    KlassHandle k_h(THREAD, klass);
    // can return a null klass
    klass = handle_resolution_exception(class_name, class_loader, protection_domain, throw_error, k_h, THREAD);
  }
  return klass;
}

klassOop SystemDictionary::resolve_or_null(symbolHandle class_name, Handle class_loader, Handle protection_domain, TRAPS) {
  assert(!THREAD->is_Compiler_thread(), "Can not load classes with the Compiler thread");
  if (FieldType::is_array(class_name())) {
    return resolve_array_class_or_null(class_name, class_loader, protection_domain, CHECK_NULL);
  } else {
    return resolve_instance_class_or_null(class_name, class_loader, protection_domain, CHECK_NULL);
  }
}
```

.... First review of resolve_instance_class_or_null doesn't spot anything interesting at first view! Maybe
I should check carefully

* On java6:
     =====

```
jdk/src/share/native/java/lang/Class.c

    public static Class<?> forName(String className)
                throws ClassNotFoundException {
        return forName0(className, true, ClassLoader.getCallerClassLoader());
    }


    /** Called after security checks have been made. */
    private static native Class forName0(String name, boolean initialize,
                                            ClassLoader loader)
        throws ClassNotFoundException;
```

hotspot/src/share/vm/prims/jvm.cpp

```
JVM_ENTRY(jclass, JVM_FindClassFromClassLoader(JNIEnv* env, const char* name,
                                               jboolean init, jobject loader,
                                               jboolean throwError))
  JVMWrapper3("JVM_FindClassFromClassLoader %s throw %s", name,
               throwError ? "error" : "exception");
  // Java libraries should ensure that name is never null...
  if (name == NULL || (int)strlen(name) > symbolOopDesc::max_length()) {
    // It's impossible to create this class;  the name cannot fit
    // into the constant pool.
    if (throwError) {
      THROW_MSG_0(vmSymbols::java_lang_NoClassDefFoundError(), name);
    } else {
      THROW_MSG_0(vmSymbols::java_lang_ClassNotFoundException(), name);
    }
  }
  symbolHandle h_name = oopFactory::new_symbol_handle(name, CHECK_NULL);
  Handle h_loader(THREAD, JNIHandles::resolve(loader));
  jclass result = find_class_from_class_loader(env, h_name, init, h_loader,
                                               Handle(), throwError, THREAD);

  if (TraceClassResolution && result != NULL) {
    trace_class_resolution(java_lang_Class::as_klassOop(JNIHandles::resolve_non_null(result)));
  }
  return result;
JVM_END
```

```
jclass find_class_from_class_loader(JNIEnv* env, Symbol* name, jboolean init, Handle loader, Handle protection_domain, jboolean throwError, TRAPS) {
  // Security Note:
  //   The Java level wrapper will perform the necessary security check allowing
  //   us to pass the NULL as the initiating class loader.
  klassOop klass = SystemDictionary::resolve_or_fail(name, loader, protection_domain, throwError != 0, CHECK_NULL);

  KlassHandle klass_handle(THREAD, klass);
  // Check if we should initialize the class
  if (init && klass_handle->oop_is_instance()) {
    klass_handle->initialize(CHECK_NULL);
  }
  return (jclass) JNIHandles::make_local(env, klass_handle->java_mirror());
}
```


hotspot/src/share/vm/classfile/systemDictionary.cpp

```
klassOop SystemDictionary::resolve_or_fail(Symbol* class_name, Handle class_loader, Handle protection_domain, bool throw_error, TRAPS) {
  klassOop klass = resolve_or_null(class_name, class_loader, protection_domain, THREAD);
  if (HAS_PENDING_EXCEPTION || klass == NULL) {
    KlassHandle k_h(THREAD, klass);
    // can return a null klass
    klass = handle_resolution_exception(class_name, class_loader, protection_domain, throw_error, k_h, THREAD);
  }
  return klass;
```

```
klassOop SystemDictionary::resolve_or_null(Symbol* class_name, Handle class_loader, Handle protection_domain, TRAPS) {
  assert(!THREAD->is_Compiler_thread(), "Can not load classes with the Compiler thread");
  if (FieldType::is_array(class_name)) {
    return resolve_array_class_or_null(class_name, class_loader, protection_domain, CHECK_NULL);
  } else if (FieldType::is_obj(class_name)) {
    ResourceMark rm(THREAD);
    // Ignore wrapping L and ;.
    TempNewSymbol name = SymbolTable::new_symbol(class_name->as_C_string() + 1,
                                   class_name->utf8_length() - 2, CHECK_NULL);
    return resolve_instance_class_or_null(name, class_loader, protection_domain, CHECK_NULL);
  } else {
    return resolve_instance_class_or_null(class_name, class_loader, protection_domain, CHECK_NULL);
  }
}
```

.... First review of resolve_instance_class_or_null doesn't spot anything interesting at first view! Maybe
I should check carefully


# So going high level....

As have been said before, on JDK 7, classForName has been replaced by ClassFinder#resolveClass

```
public static Class classForName(String name) throws ClassNotFoundException
Deprecated! As - of JDK version 7, replaced by ClassFinder#resolveClass(String) .

ClassFinder doesn't exist on JDK 6, so digging into JDK 7:

     * @see #resolveClass(String,ClassLoader)
     */
    public static Class<?> resolveClass(String name) throws ClassNotFoundException {
        return resolveClass(name, null);
    }

calls with loader == null....

    /**
     * Returns the {@code Class} object associated with
     * the class or interface with the given string name,
     * using the given class loader.
     * <p>
     * The {@code name} can denote an array class
     * (see {@link Class#getName} for details).
     * <p>
     * If the parameter {@code loader} is null,
     * the class is loaded through the default class loader.
     * <p>
     * This method can be used to obtain
     * any of the {@code Class} objects
     * representing {@code void} or primitive Java types:
     * {@code char}, {@code byte}, {@code short},
     * {@code int}, {@code long}, {@code float},
     * {@code double} and {@code boolean}.
     *
     * @param name    fully qualified name of the desired class
     * @param loader  class loader from which the class must be loaded
     * @return class object representing the desired class
     *
     * @throws ClassNotFoundException  if the class cannot be located
     *                                 by the specified class loader
     *
     * @see #findClass(String,ClassLoader)
     * @see PrimitiveTypeMap#getType(String)
     */
    public static Class<?> resolveClass(String name, ClassLoader loader) throws ClassNotFoundException {
        Class<?> type = PrimitiveTypeMap.getType(name);
        return (type == null)
                ? findClass(name, loader)
                : type;
    }


    /**
     * Returns the {@code Class} object associated with
     * the class or interface with the given string name,
     * using the given class loader.
     * <p>
     * The {@code name} can denote an array class
     * (see {@link Class#getName} for details).
     * <p>
     * If the parameter {@code loader} is null,
     * the class is loaded through the default class loader.
     *
     * @param name    fully qualified name of the desired class
     * @param loader  class loader from which the class must be loaded
     * @return class object representing the desired class
     *
     * @throws ClassNotFoundException  if the class cannot be located
     *                                 by the specified class loader
     *
     * @see #findClass(String,ClassLoader)
     * @see Class#forName(String,boolean,ClassLoader)
     */
    public static Class<?> findClass(String name, ClassLoader loader) throws ClassNotFoundException {
        if (loader != null) {
            try {
                return Class.forName(name, false, loader);
            } catch (ClassNotFoundException exception) {
                // use default class loader instead
            } catch (SecurityException exception) {
                // use default class loader instead
            }
        }
        return findClass(name);
    }
```

Will call.... so here we go.... I suppose the difference could be how
Java 7 calls to Class.forName maybe....:

```
    /**
     * Returns the {@code Class} object associated
     * with the class or interface with the given string name,
     * using the default class loader.
     * <p>
     * The {@code name} can denote an array class
     * (see {@link Class#getName} for details).
     *
     * @param name  fully qualified name of the desired class
     * @return class object representing the desired class
     *
     * @throws ClassNotFoundException  if the class cannot be located
     *                                 by the specified class loader
     *
     * @see Class#forName(String)
     * @see Class#forName(String,boolean,ClassLoader)
     * @see ClassLoader#getSystemClassLoader()
     * @see Thread#getContextClassLoader()
     */
    public static Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            if (loader == null) {
                // can be null in IE (see 6204697)
                loader = ClassLoader.getSystemClassLoader();
            }
            if (loader != null) {
                return Class.forName(name, false, loader);
            }

        } catch (ClassNotFoundException exception) {
            // use current class loader instead
        } catch (SecurityException exception) {
            // use current class loader instead
        }
        return Class.forName(name);
    }
```

In Java6

```
	at java.security.AccessControlContext.checkPermission(Unknown Source)
	at java.security.AccessController.checkPermission(Unknown Source)
	at java.lang.SecurityManager.checkPermission(Unknown Source)
	at java.lang.SecurityManager.checkPackageAccess(Unknown Source)
	at sun.plugin2.applet.Applet2SecurityManager.checkPackageAccess(Unknown Source)
	at sun.misc.Launcher$AppClassLoader.loadClass(Unknown Source)
	at java.lang.ClassLoader.loadClass(Unknown Source)
	at sun.plugin2.applet.Plugin2ClassLoader.loadClass0(Unknown Source)
	at sun.plugin2.applet.Plugin2ClassLoader.loadClass(Unknown Source)
	at sun.plugin2.applet.Plugin2ClassLoader.loadClass0(Unknown Source)
	at sun.plugin2.applet.Plugin2ClassLoader.loadClass(Unknown Source)
	at sun.plugin2.applet.Plugin2ClassLoader.loadClass(Unknown Source)
	at java.lang.ClassLoader.loadClass(Unknown Source)
	at java.lang.Class.forName0(Native Method)
	at java.lang.Class.forName(Unknown Source)
```

My feeling is.... on Java7 the sun.plugin2.applet.Plugin2ClassLoader is not
being used..... sooo.... whhich one?.... maybe:

```
ClassLoader loader = Thread.currentThread().getContextClassLoader();
if (loader == null) {
	// can be null in IE (see 6204697)
	loader = ClassLoader.getSystemClassLoader();
}
```

maybe??? not sure 100% sorry, I would need debug it to see a little better...

The difference, could be, with JDK6, where the ClassFinder doesn't exist, is which
forName would be call and ClassLoader.getCallerClassLoader() will be used.... could be???

```
    /**
     * Returns the {@code Class} object associated with the class or
     * interface with the given string name.  Invoking this method is
     * equivalent to:
     *
     * <blockquote>
     *  {@code Class.forName(className, true, currentLoader)}
     * </blockquote>
     *
     * where {@code currentLoader} denotes the defining class loader of
     * the current class.
     *
     * <p> For example, the following code fragment returns the
     * runtime {@code Class} descriptor for the class named
     * {@code java.lang.Thread}:
     *
     * <blockquote>
     *   {@code Class t = Class.forName("java.lang.Thread")}
     * </blockquote>
     * <p>
     * A call to {@code forName("X")} causes the class named
     * {@code X} to be initialized.
     *
     * @param      className   the fully qualified name of the desired class.
     * @return     the {@code Class} object for the class with the
     *             specified name.
     * @exception LinkageError if the linkage fails
     * @exception ExceptionInInitializerError if the initialization provoked
     *            by this method fails
     * @exception ClassNotFoundException if the class cannot be located
     */
    public static Class<?> forName(String className)
                throws ClassNotFoundException {
        return forName0(className, true, ClassLoader.getCallerClassLoader());
    }
```
