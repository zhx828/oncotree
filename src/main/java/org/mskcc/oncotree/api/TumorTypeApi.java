package org.mskcc.oncotree.api;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponses;
import org.mskcc.oncotree.model.TumorType;
import org.mskcc.oncotree.model.TumorTypePostResp;
import org.mskcc.oncotree.model.TumorTypeQueries;
import org.mskcc.oncotree.model.TumorTypeQuery;
import org.mskcc.oncotree.utils.TumorTypesUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Controller
@RequestMapping(value = "/tumorType", produces = {APPLICATION_JSON_VALUE})
@Api(value = "/tumorType", description = "the tumorType API")
@javax.annotation.Generated(value = "class io.swagger.codegen.languages.SpringMVCServerCodegen", date = "2016-02-24T21:00:49.581Z")
public class TumorTypeApi {


    @ApiOperation(value = "Tumor Types", notes = "...", response = TumorType.class, responseContainer = "List")
    @ApiResponses(value = {
        @io.swagger.annotations.ApiResponse(code = 200, message = "An array of tumor types"),
        @io.swagger.annotations.ApiResponse(code = 200, message = "Unexpected error")})
    @RequestMapping(value = "",
        produces = {"application/json"},
        method = RequestMethod.GET)
    public ResponseEntity<List<TumorType>> tumorTypeGet(@ApiParam(value = "Query type. It could be 'code', 'name', 'mainType', 'nci', 'umls' or 'color'", required = true) @RequestParam(value = "queryType", required = true) String queryType,
                                                        @ApiParam(value = "The query content", required = true) @RequestParam(value = "query", required = true) String query
    ){

        List<TumorType> matchedTumorTypes = TumorTypesUtil.findTumorTypes(queryType, query);

        return new ResponseEntity<List<TumorType>>(matchedTumorTypes, HttpStatus.OK);
    }


    @ApiOperation(value = "Tumor Types", notes = "...", response = TumorTypePostResp.class, responseContainer = "List")
    @io.swagger.annotations.ApiResponses(value = {
        @io.swagger.annotations.ApiResponse(code = 200, message = "An array of tumor types"),
        @io.swagger.annotations.ApiResponse(code = 200, message = "Unexpected error")})
    @RequestMapping(value = "",
        produces = {"application/json"},
        consumes = {"application/json"},
        method = RequestMethod.POST)
    public ResponseEntity<List<TumorTypePostResp>> tumorTypePost(

        @ApiParam(value = "", required = true) @RequestBody TumorTypeQueries queries){

        List<TumorTypePostResp> matchedTumorTypes = new ArrayList<>();

        for (TumorTypeQuery query : queries) {
            matchedTumorTypes.add((TumorTypePostResp)TumorTypesUtil.findTumorTypes(query));
        }
        return new ResponseEntity<List<TumorTypePostResp>>(matchedTumorTypes, HttpStatus.OK);
    }
}
