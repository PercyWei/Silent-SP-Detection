import json

from agent_app import globals
globals.lang = "Java"
from agent_app.static_analysis.java_ast_parse import ASTParser


parser = ASTParser()

java_code = """package MyASTParser;
import java.io.IOException;
import java.util.*;
import org.apache.commons.cli.*;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.core.dom.*;
record LineRange(int startLine, int endLine) {}
record FileSearchIndexData(
        Map<Integer, String> imports,
        Map<String, LineRange> classes,
        Map<String, LineRange> interfaces,
        Map<String, Map<String, List<LineRange>>> classToMethods,
        Map<String, Map<String, List<LineRange>>> classToInnerClasses,
        Map<String, Map<String, List<LineRange>>> classToInnerInterfaces
) {}
enum SimNodeType {
    MODULE("module"),
    UNIT("unit"),
    INTERFACE("interface"),
    CLASS("class"),
    CLASS_UNIT("class_unit"),
    CLASS_INTERFACE("class_interface"),
    CLASS_CLASS("class_class"),
    CLASS_METHOD("class_method");
    private final String value;
    SimNodeType(String value) {
        this.value = value;
    }
    public String getValue() {
        return value;
    }
}
class SimNode {
    public int id;
    public Integer father;  // null 为father
    public String type;
    public String ast;
    public String name;
    public LineRange range;
    public SimNode(int id, Integer father, SimNodeType type, String ast, String name, LineRange range) {
        this.id = id;
        this.father = father;
        this.type = type.getValue();
        this.ast = ast;
        this.name = name;
        this.range = range;
    }
    public List<Integer> getFullRange() {
        List<Integer> fullRange = new ArrayList<>();
        for (int i = this.range.startLine(); i <= this.range.endLine(); i++) {
            fullRange.add(i);
        }
        return fullRange;
    }
}
public class SimNodeParser {
    static CompilationUnit cu;
    // (1) Simple Node data
    static Integer curNodeId = null;
    static Map<Integer, SimNode> allNodes = new HashMap<>();     // Simple Node id -> Simple Node
    static Map<Integer, Integer> li2node_map = new HashMap<>();  // line id -> Simple Node id
    // (2) Search Indexes
    static Map<String, List<LineRange>> allInterfaces = new HashMap<>();  // interface name -> [range]
    static Map<String, List<LineRange>> allClasses = new HashMap<>();     // class name     -> [range]
    static Map<String, Map<String, List<LineRange>>> allInclassInterfaces = new HashMap<>();  // {class name -> {interface name -> [range]}
    static Map<String, Map<String, List<LineRange>>> allInclassClasses = new HashMap<>();     // {class name -> {class name     -> [range]}
    static Map<String, Map<String, List<LineRange>>> allInclassMethods = new HashMap<>();     // {class name -> {method name    -> [range]]}
    // (3) Import statements
    static Map<String, String> allImports = new HashMap<>();  // import statement -> import name
    private static LineRange getLineRangeFromASTNode(ASTNode node) {
        int start = node.getStartPosition();
        int length = node.getLength();
        int end = start + length - 1;
        int startLine = cu.getLineNumber(start);
        int endLine = cu.getLineNumber(end);
        return new LineRange(startLine, endLine);
    }
    private static ASTParser setASTParser() {
        ASTParser parser = ASTParser.newParser(AST.JLS13);
        parser.setKind(ASTParser.K_COMPILATION_UNIT);
        Map<String, String> compilerOptions = JavaCore.getOptions();
        parser.setCompilerOptions(compilerOptions);
        parser.setResolveBindings(true);
        String unitName = "parser.java";
        parser.setUnitName(unitName);
        parser.setEnvironment(null, null, null, true);
        parser.setBindingsRecovery(true);
        return parser;
    }
    private static SimNode updateAllNodes(
            Integer fatherNodeId,
            SimNodeType nodeType,
            String nodeAstType,
            String nodeName,
            LineRange nodeRange
    ) {
        assert curNodeId != null;
        SimNode curNode = new SimNode(curNodeId, fatherNodeId, nodeType, nodeAstType, nodeName, nodeRange);
        allNodes.put(curNodeId, curNode);
        curNodeId += 1;
        return curNode;
    }
    private static void updateLine2NodeMap(SimNode lineNode) {
        for (Integer lineId: lineNode.getFullRange()) {
            assert lineId != null && !li2node_map.containsKey(lineId);
            li2node_map.put(lineId, lineNode.id);
        }
    }
    private static SimNode updateWithRoot() {
        curNodeId = 0;
        assert cu.getNodeType() == 15;
        String rootASTType = "COMPILATION_UNIT";
        String rootName = "";
        LineRange rootRange = getLineRangeFromASTNode(cu);
        SimNode rootSimNode = updateAllNodes(null, SimNodeType.MODULE, rootASTType, rootName, rootRange);
        return rootSimNode;
    }
    private static void updateWithImportDecl(ImportDeclaration astNode, int fatherNodeId) {
        String unitASTType = Integer.toString(astNode.getNodeType());
        String unitName = "";
        LineRange unitRange = getLineRangeFromASTNode(astNode);
        SimNode unitSimNode = updateAllNodes(fatherNodeId, SimNodeType.UNIT, unitASTType, unitName, unitRange);
        updateLine2NodeMap(unitSimNode);
        String importStmt = astNode.toString();
        String importName = astNode.getName().toString();
        allImports.put(importStmt, importName);
    }
    private static void updateWithInterfaceDecl(TypeDeclaration astNode, int fatherNodeId) {
        assert astNode.isInterface();
        String ifaceASTType = Integer.toString(astNode.getNodeType());
        String ifaceName = astNode.getName().getIdentifier();
        LineRange ifaceRange = getLineRangeFromASTNode(astNode);
        SimNode ifaceSimNode = updateAllNodes(fatherNodeId, SimNodeType.INTERFACE, ifaceASTType, ifaceName, ifaceRange);
        updateLine2NodeMap(ifaceSimNode);
        allInterfaces.computeIfAbsent(ifaceName, k -> new ArrayList<>()).add(ifaceRange);
    }
    private static void updateWithClassBody(TypeDeclaration astNode, SimNode classSimNode) {
        assert !astNode.isInterface() && Objects.equals(classSimNode.type, SimNodeType.CLASS_CLASS.getValue());
        List<BodyDeclaration> classChildren = astNode.bodyDeclarations();
        SimNodeType childType;
        String childASTType;
        String childName;
        LineRange childRange;
        SimNode childSimNode;
        // (1) Add class signature
        BodyDeclaration firstChild = classChildren.get(0);
        int firstChildStart = getLineRangeFromASTNode(firstChild).startLine();
        if (classSimNode.range.startLine() < firstChildStart) {
            childType = SimNodeType.CLASS_UNIT;
            childASTType = "class_name";
            childName = "";
            childRange = new LineRange(classSimNode.range.startLine(), firstChildStart - 1);
            childSimNode = updateAllNodes(classSimNode.id, childType, childASTType, childName, childRange);
            updateLine2NodeMap(childSimNode);
        }
        // (2) Add top-level class children
        Map<String, List<LineRange>> inclassInterfaces = new HashMap<>();  // inclass interface name -> [range]
        Map<String, List<LineRange>> inclassClasses = new HashMap<>();     // inclass class name     -> [range]
        Map<String, List<LineRange>> inclassMethods = new HashMap<>();     // inclass method name    -> [range]
        for (BodyDeclaration childNode : classChildren) {
            childASTType = Integer.toString(astNode.getNodeType());
            childRange = getLineRangeFromASTNode(childNode);
            if (childNode instanceof TypeDeclaration childTypeNode) {
                // 1. Inner interface or class
                childName = childTypeNode.getName().getIdentifier();
                if (childTypeNode.isInterface()) {
                    childType = SimNodeType.CLASS_INTERFACE;
                    inclassInterfaces.computeIfAbsent(childName, k -> new ArrayList<>()).add(childRange);
                } else {
                    childType = SimNodeType.CLASS_CLASS;
                    inclassClasses.computeIfAbsent(childName, k -> new ArrayList<>()).add(childRange);
                }
            }else if (childNode instanceof MethodDeclaration childMethodNode) {
                // 2. Method or constructor
                childName = childMethodNode.getName().getIdentifier();
                childType = SimNodeType.CLASS_METHOD;
                inclassMethods.computeIfAbsent(childName, k -> new ArrayList<>()).add(childRange);
            } else {
                // 3. Other statement
                childName = "";
                childType = SimNodeType.CLASS_UNIT;
            }
            childSimNode = updateAllNodes(classSimNode.id, childType, childASTType, childName, childRange);
            updateLine2NodeMap(childSimNode);
        }
        allInclassInterfaces.computeIfAbsent(classSimNode.name, k -> new HashMap<>()).putAll(inclassInterfaces);
        allInclassClasses.computeIfAbsent(classSimNode.name, k -> new HashMap<>()).putAll(inclassClasses);
        allInclassMethods.computeIfAbsent(classSimNode.name, k -> new HashMap<>()).putAll(inclassMethods);
    }
    private static void updateWithClassDecl(TypeDeclaration astNode, int fatherNodeId) {
        assert !astNode.isInterface();
        String classASTType = Integer.toString(astNode.getNodeType());
        String className = astNode.getName().getIdentifier();
        LineRange classRange = getLineRangeFromASTNode(astNode);
        SimNode classSimNode = updateAllNodes(fatherNodeId, SimNodeType.CLASS, classASTType, className, classRange);
        updateWithClassBody(astNode, classSimNode);
        allClasses.computeIfAbsent(className, k -> new ArrayList<>()).add(classRange);
    }
    private static void updateWithOther(ASTNode astNode, int fatherNodeId) {
        String unitASTType = Integer.toString(astNode.getNodeType());
        // NOTE: For now, we only consider the names of the following constructs:
        // - MethodDeclaration
        // - ClassDeclaration
        // - InterfaceDeclaration
        // - EnumDeclaration
        // - AnnotationTypeDeclaration
        String unitName;
        if (astNode instanceof AbstractTypeDeclaration) {
            unitName = ((AbstractTypeDeclaration) astNode).getName().getIdentifier();
        } else if (astNode instanceof MethodDeclaration) {
            unitName = ((MethodDeclaration) astNode).getName().getIdentifier();
        } else {
            unitName = "";
        }
        LineRange unitRange = getLineRangeFromASTNode(astNode);
        SimNode unitSimNode = updateAllNodes(fatherNodeId, SimNodeType.UNIT, unitASTType, unitName, unitRange);
        updateLine2NodeMap(unitSimNode);
    }
    public static void parse(String codeString) throws IOException {
        // ------------ Step 1: Set ASTParser ------------ //
        ASTParser parser = setASTParser();
        // ------------ Step 2: Parse the source code ------------ //
        parser.setSource(codeString.toCharArray());
        cu = (CompilationUnit) parser.createAST(null);
        // ------------ Step 3: Extract Simple Nodes and build search indexes ------------ //
        // (0) Add root node
        SimNode rootSimNode = updateWithRoot();
        // NOTE: Following method 'accept0' in CompilationUnit node to traverse its children
        // (1) Visit module declaration
        if (cu.getAST().apiLevel() >= 9) {
            ModuleDeclaration moduleDecl = cu.getModule();
            if (moduleDecl != null) {
                updateWithOther(moduleDecl, rootSimNode.id);
            }
        }
        // (2) Visit package declaration
        PackageDeclaration packageDecl = cu.getPackage();
        if (packageDecl != null) {
            updateWithOther(packageDecl, rootSimNode.id);
        }
        // (3) Visit import statements
        List<ImportDeclaration> importDecls = cu.imports();
        for (ImportDeclaration importDecl : importDecls) {
            updateWithImportDecl(importDecl, rootSimNode.id);
        }
        // (4) Visit all top-level type declarations
        @SuppressWarnings("unchecked")
        List<AbstractTypeDeclaration> absTypeDecls = (List<AbstractTypeDeclaration>) cu.types();
        for (AbstractTypeDeclaration absTypeDecl : absTypeDecls) {
            if (absTypeDecl instanceof TypeDeclaration typeDecl) {
                if (typeDecl.isInterface()) {
                    updateWithInterfaceDecl(typeDecl, rootSimNode.id);
                } else {
                    updateWithClassDecl(typeDecl, rootSimNode.id);
                }
            } else {
                updateWithOther(absTypeDecl, rootSimNode.id);
            }
        }
//        // ------------ Step 4: Output JSON data ------------ //
//        FileSearchIndexData fileSearchIndexData = new FileSearchIndexData(allImports, allClasses, allInterfaces,
//                allInclassMethods, allInclassClasses, allInclassInterfaces);
//
//        ObjectMapper objectMapper = new ObjectMapper();
//        String jsonData = objectMapper.writeValueAsString(fileSearchIndexData);
//
//        System.out.println(jsonData);
    }
    public static void main(String[] args) throws IOException {
        int maxFileLen = 5000;
        Utils.maxFileLength = maxFileLen;
        // Set argument parser
        Options options = new Options();
        options.addOption("f", "filter-blank", false, "Filter blank lines in code");
        options.addOption("s", "source-file-path", true, "File path to source code");
        CommandLineParser parser = new DefaultParser();
        // Main
        try {
            CommandLine cmd = parser.parse(options, args);
            boolean filterBlank = cmd.hasOption("f");
            String sourceFilePath = cmd.getOptionValue("s");
            String codeString = Utils.readFileToString(sourceFilePath);
            if (filterBlank) {
                codeString = Utils.removeBlankLines(codeString);
            }
            parse(codeString);
        } catch (ParseException e) {
            System.out.println("Need to pass parameters: --filter-blank [bool] --source-file-path [string]");
            e.printStackTrace();
        }
    }
}
"""
java_code_fpath = "/root/projects/VDTest/agent_app/static_analysis/java-static-analysis/src/test/resources/Example4.java"
parser.set(code_fpath=java_code_fpath)
parser.parse_java_code()

print(f"All interfaces: \n{json.dumps(parser.all_interfaces, indent=4)}\n\n")
print(f"All classes: \n{json.dumps(parser.all_classes, indent=4)}\n\n")
print(f"All inclass interfaces: \n{json.dumps(parser.all_inclass_interfaces, indent=4)}\n\n")
print(f"All inclass classes: \n{json.dumps(parser.all_inclass_classes, indent=4)}\n\n")
print(f"All inclass methods: \n{json.dumps(parser.all_inclass_methods, indent=4)}\n\n")
