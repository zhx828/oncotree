package org.mskcc.oncotree.utils;

import com.univocity.parsers.tsv.TsvParser;
import com.univocity.parsers.tsv.TsvParserSettings;
import org.mskcc.oncotree.model.TumorType;
import org.mskcc.oncotree.model.TumorTypeQuery;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by Hongxin on 2/25/16.
 */
public class TumorTypesUtil {
    private static String TUMOR_TREE_FILE = "classpath:tumor_tree.txt";
    private static List<String> TumorTypeKeys = Arrays.asList("code", "name", "nci", "umls", "maintype", "color");

    public static Map<String, Object> getTumorTypes() {
        Map<String, Object> tumorTypes = new HashMap<>();
        TsvParserSettings settings = new TsvParserSettings();

        //the line separator sequence is defined here to ensure systems such as MacOS and Windows
        //are able to process this file correctly (MacOS uses '\r'; and Windows uses '\r\n').
        settings.getFormat().setLineSeparator("\n");

        // creates a TSV parser
        TsvParser parser = new TsvParser(settings);

        // parses all rows in one go.
        List<String[]> allRows = parser.parseAll(getReader(TUMOR_TREE_FILE));

        Map<String, Object> tumorType = new HashMap<>();
        tumorType.put("children", new HashMap<>());
        tumorType.put("code", "TISSUE");
        tumorType.put("name", "Tissue");

        //Iterate each row and assign tumor type to parent following the order of appearing
        for (String[] row : allRows.subList(1, allRows.size())) {
            tumorType.put("children", attachTumorType((Map<String, Object>) tumorType.get("children"), row, 0));
        }

        //Attach a root node in the JSON file
        tumorTypes.put("TISSUE", tumorType);
        return tumorTypes;
    }

    public static List<TumorType> findTumorTypes(String key, String keyword) {
        List<TumorType> tumorTypes = new ArrayList<>();
        key = normalizeTumorTypeKey(key);
        if (TumorTypeKeys.contains(key)) {
            tumorTypes = findTumorType((Map<String, Object>) CacheUtil.getTumorTypes().get("TISSUE"), tumorTypes, key, keyword);
        }
        return tumorTypes;
    }

    public static List<TumorType> findTumorTypes(TumorTypeQuery query) {
        List<TumorType> tumorTypes = new ArrayList<>();
        String key = normalizeTumorTypeKey(query.getQueryType());
        if (TumorTypeKeys.contains(key)) {
            tumorTypes = findTumorType((Map<String, Object>) CacheUtil.getTumorTypes().get("TISSUE"), tumorTypes, key, query.getQuery());
        }
        return tumorTypes;
    }

    public static InputStream getTumorTypeInputStream() {
        return getInputStream(TUMOR_TREE_FILE);
    }

    private static List<TumorType> findTumorType(Map<String, Object> allTumorTypes, List<TumorType> matchedTumorTypes, String key, String keyword) {
        Map<String, Object> childrenTumorTypes = (Map<String, Object>) allTumorTypes.get("children");
        List<String> childrenCode = new ArrayList<>();
        childrenCode.addAll(childrenTumorTypes.keySet());

        if (allTumorTypes.containsKey(key) && allTumorTypes.get(key).equals(keyword)) {
            TumorType tumorType = new TumorType();
            tumorType.setCode((String) allTumorTypes.get("code"));
            tumorType.setName((String) allTumorTypes.get("name"));
            tumorType.setNCI((String) allTumorTypes.get("nci"));
            tumorType.setUMLS((String) allTumorTypes.get("umls"));
            tumorType.setMainType((String) allTumorTypes.get("mainType"));
            tumorType.setColor((String) allTumorTypes.get("color"));
            tumorType.setChildren(childrenCode);
            matchedTumorTypes.add(tumorType);
        }

        if (childrenTumorTypes.size() > 0) {
            for (String code : childrenCode) {
                matchedTumorTypes = findTumorType((Map<String, Object>) childrenTumorTypes.get(code), matchedTumorTypes, key, keyword);
            }
        }
        return matchedTumorTypes;
    }

    private static String normalizeTumorTypeKey(String key) {
        key = key.toLowerCase();
        key.replaceAll("[^a-z]+", "");
        return key;
    }

    /**
     * Attach children to parent node.
     *
     * @param tumorTypes
     * @param row        One row of text file
     * @param index      Current index of row. It will be increased everytime this function has been called.
     * @return parent node.
     */
    private static Map<String, Object> attachTumorType(Map<String, Object> tumorTypes, String[] row, int index) {
        if (index < 5 && row.length > index && row[index] != null && !row[index].isEmpty()) {
            Map<String, String> result = parseCodeName(row[index]);
            if (result.containsKey("code")) {
                Map<String, Object> tumorType = new HashMap<>();
                if (!tumorTypes.containsKey(result.get("code"))) {
                    tumorType.put("children", new HashMap<>());
                    tumorType.put("code", result.get("code"));
                    tumorType.put("name", result.get("name"));
                    tumorType.put("mainType", row.length > 5 ? row[5] : "");
                    tumorType.put("color", row.length > 6 ? row[6] : "");
                    tumorType.put("nci", row.length > 7 ? row[7] : "");
                    tumorType.put("umls", row.length > 8 ? row[8] : "");
                } else {
                    tumorType = (Map<String, Object>) tumorTypes.get(result.get("code"));
                }
                tumorType.put("children", attachTumorType((Map<String, Object>) tumorType.get("children"), row, ++index));
                tumorTypes.put(result.get("code"), tumorType);
            }
        }
        return tumorTypes;
    }

    /**
     * Parsing cell content into tumor type code and tumor type name.
     *
     * @param content One cell of each row.
     * @return The map of current tumor type. It includes 'code' and 'name'.
     */
    private static HashMap<String, String> parseCodeName(String content) {
        HashMap<String, String> result = new HashMap<>();

        Pattern pattern = Pattern.compile("([^\\(]+)\\(([^\\)]+)\\)");

        Matcher matcher = pattern.matcher(content);
        if (matcher.matches()) {
            result.put("name", matcher.group(1).trim());
            result.put("code", matcher.group(2).trim());
        }
        return result;
    }

    /**
     * Get tumor type text file input stream.
     *
     * @param relativePath Tumor type text file path.
     * @return Input stream
     */
    private static InputStreamReader getReader(String relativePath) {
        try {
            return new InputStreamReader(getInputStream(relativePath), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static InputStream getInputStream(String relativePath) {
        ApplicationContext applicationContext = new ClassPathXmlApplicationContext();
        Resource resource = applicationContext.getResource(relativePath);
        try {
            return resource.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
