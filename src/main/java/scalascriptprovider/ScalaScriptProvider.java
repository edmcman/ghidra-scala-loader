/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.script;

import java.io.*;
import java.util.*;

import java.lang.ClassLoader;

import java.net.URL;
import java.net.MalformedURLException;
import java.net.URLClassLoader;

import scala.collection.JavaConversions;
import scala.tools.nsc.MainClass;

import javax.tools.*;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject.Kind;

import generic.io.NullPrintWriter;
import generic.jar.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.Msg;

public class ScalaScriptProvider extends GhidraScriptProvider {

  @Override
  public String getDescription() {
    return "Scala";
  }

  @Override
  public String getExtension() {
    return ".scala";
  }

  static ResourceFile getClassFileByResourceFile(ResourceFile sourceFile, String rawName) {
    String javaAbsolutePath = sourceFile.getAbsolutePath();
    String classAbsolutePath = javaAbsolutePath.replace(".java", ".class");

    return new ResourceFile(classAbsolutePath);
  }

  @Override
  public boolean deleteScript(ResourceFile scriptSource) {
    // Assuming script is in default java package, so using script's base name as class name.
    File clazzFile = getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource));
    clazzFile.delete();
    return super.deleteScript(scriptSource);
  }

  @Override
  public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer) throws GhidraScriptLoadException {

    if (writer == null) {
      writer = new NullPrintWriter();
    }

    try {
      compile(sourceFile, writer);

      Class<?> clazz = getScriptClass(sourceFile);
  
			if (GhidraScript.class.isAssignableFrom(clazz)) {
				GhidraScript script = (GhidraScript) clazz.getDeclaredConstructor().newInstance();
				script.setSourceFile(sourceFile);
				return script;
			}

      throw new GhidraScriptLoadException(
				"Ghidra scripts in Java must extend " + GhidraScript.class.getName() + ". " +
					sourceFile.getName() + " does not.");  
    }
		catch (ClassNotFoundException e) {
			throw new GhidraScriptLoadException("The class could not be found. " +
				"It must be the public class of the .java file: " + e.getMessage(), e);
		}
		catch (NoClassDefFoundError e) {
			throw new GhidraScriptLoadException("The class could not be found or loaded, " +
				"perhaps due to a previous initialization error: " + e.getMessage(), e);
		}
		catch (ExceptionInInitializerError e) {
			throw new GhidraScriptLoadException(
				"Error during class initialization: " + e.getException(), e.getException());
		}
		catch (Exception e) {
			throw new GhidraScriptLoadException("Unexpected error: " + e);
		}

  }

  /**
   * Gets the class file corresponding to the given source file and class name.  
   * If the class is in a package, the class name should include the full 
   * package name.
   * 
   * @param sourceFile The class's source file.
   * @param className The class's name (including package if applicable).
   * @return The class file corresponding to the given source file and class name. 
   */
  protected File getClassFile(ResourceFile sourceFile, String className) {
    ResourceFile resourceFile =
      getClassFileByResourceFile(sourceFile, className);

    File file = resourceFile.getFile(false);
    return file;
  }

  protected boolean compile(ResourceFile sourceFile, final PrintWriter writer)
    throws ClassNotFoundException {

    if (!doCompile(sourceFile, writer)) {
      writer.flush(); // force any error messages out
      throw new ClassNotFoundException("Unable to compile class aw: " + sourceFile.getName());
    }

    writer.println("Successfully compiled: " + sourceFile.getName());

    return true;
  }

  private ResourceFile outputDir(ResourceFile sourceFile) {
    return sourceFile.getParentFile();
  }

  private boolean doCompile(ResourceFile sourceFile, final PrintWriter writer) {

    List<ResourceFileJavaFileObject> list = new ArrayList<>();
    list.add(
      new ResourceFileJavaFileObject(sourceFile.getParentFile(), sourceFile, Kind.SOURCE));

    String outputDirectory = outputDir(sourceFile).getAbsolutePath();
    Msg.trace(this, "Compiling script " + sourceFile + " to dir " + outputDirectory);

    //Settings s = new Settings();
    MainClass d = new MainClass ();
    List<String> args = new ArrayList<String>();
    args.add("-g:source");
    args.add("-d");
    args.add(outputDirectory);
    args.add("-sourcepath");
    args.add(getSourcePath());
    args.add("-classpath");
    args.add(getClassPath());
    args.add(sourceFile.getAbsolutePath ());

    return d.process (args.toArray (new String[0]));
  }

  private List<Class<?>> getParentClasses(ResourceFile scriptSourceFile) {

    Class<?> scriptClass = getScriptClass(scriptSourceFile);
    if (scriptClass == null) {
      return null; // special signal that there was a problem
    }

    List<Class<?>> parentClasses = new ArrayList<>();
    Class<?> superClass = scriptClass.getSuperclass();
    while (superClass != null) {
      if (superClass.equals(GhidraScript.class)) {
        break; // not interested in the built-in classes
      }
      else if (superClass.equals(HeadlessScript.class)) {
        break; // not interested in the built-in classes
      }
      parentClasses.add(superClass);
      superClass = superClass.getSuperclass();
    }
    return parentClasses;
  }

  private Class<?> getScriptClass(ResourceFile scriptSourceFile) {
    String clazzName = GhidraScriptUtil.getBaseName(scriptSourceFile);
    try {
      URL classURL = outputDir(scriptSourceFile).getFile(false).toURI().toURL();
      ClassLoader cl = new URLClassLoader(new URL[] {classURL});
      Class<?> clazz = cl.loadClass(clazzName);
      return clazz;
    }
    catch (NoClassDefFoundError | ClassNotFoundException e) {
      Msg.error(this, "Unable to find class file for script file: " + scriptSourceFile, e);
    }
    catch (MalformedURLException e) {
      Msg.error(this, "Malformed URL exception:", e);
    }
    return null;
  }

  private ResourceFile getSourceFile(Class<?> c) {
    // check all script paths for a dir named
    String classname = c.getName();
    String filename = classname.replace('.', '/') + ".scala";

    List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();
    for (ResourceFile dir : scriptDirs) {
      ResourceFile possibleFile = new ResourceFile(dir, filename);
      if (possibleFile.exists()) {
        return possibleFile;
      }
    }

    return null;
  }

  private String getSourcePath() {
    String classpath = System.getProperty("java.class.path");
    List<ResourceFile> dirs = GhidraScriptUtil.getScriptSourceDirectories();
    for (ResourceFile dir : dirs) {
      classpath += (System.getProperty("path.separator") + dir.getAbsolutePath());
    }
    return classpath;
  }

  private String getClassPath() {
    String classpath = System.getProperty("java.class.path");
    // List<ResourceFile> dirs = GhidraScriptUtil.getScriptBinDirectories();
    // for (ResourceFile dir : dirs) {
    // 	classpath += (System.getProperty("path.separator") + dir.getAbsolutePath());
    // }
    return classpath;
  }

  @Override
  public void createNewScript(ResourceFile newScript, String category) throws IOException {
    assert (false);
  }

  @Override
  public String getCommentCharacter() {
    return "//";
  }
}
