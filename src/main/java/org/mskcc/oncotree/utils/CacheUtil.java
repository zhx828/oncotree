package org.mskcc.oncotree.utils;

import java.util.Map;

/**
 * Created by Hongxin on 2/25/16.
 */
public class CacheUtil {
    public static Map<String, Object> tumorTypes = null;

    public static Map<String, Object> getTumorTypes() {
        //Don't cache tumor types file. It may be changed anytime.
//        if (tumorTypes == null) {
            tumorTypes = TumorTypesUtil.getTumorTypes();
//        }
        return tumorTypes;
    }
}
