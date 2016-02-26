package org.mskcc.oncotree.api;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponses;
import org.mskcc.oncotree.utils.CacheUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Controller
@RequestMapping(value = "/tumorTypes", produces = {APPLICATION_JSON_VALUE})
@Api(value = "/tumorTypes", description = "the tumorTypes API")
@javax.annotation.Generated(value = "class io.swagger.codegen.languages.SpringMVCServerCodegen", date = "2016-02-24T21:00:49.581Z")
public class TumorTypesApi {


    @ApiOperation(value = "Tumor Types", notes = "Return all available tumor types.")
    @ApiResponses(value = {
        @io.swagger.annotations.ApiResponse(code = 200, message = "Nested tumor types object."),
        @io.swagger.annotations.ApiResponse(code = 200, message = "Unexpected error")})
    @RequestMapping(value = "",
        produces = {"application/json"},

        method = RequestMethod.GET)

    public ResponseEntity<Object> tumorTypesGet()
        throws Exception {

        return new ResponseEntity<Object>(CacheUtil.getTumorTypes(), HttpStatus.OK);
    }

}
