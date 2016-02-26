package org.mskcc.oncotree.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.Objects;


@ApiModel(description = "")
@javax.annotation.Generated(value = "class io.swagger.codegen.languages.SpringMVCServerCodegen", date = "2016-02-24T17:47:20.686Z")
public class TumorTypeQuery  {
  
  private String queryType = null;
  private String query = null;
  private String queryId = null;

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("queryType")
  public String getQueryType() {
    return queryType;
  }
  public void setQueryType(String queryType) {
    this.queryType = queryType;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("query")
  public String getQuery() {
    return query;
  }
  public void setQuery(String query) {
    this.query = query;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("queryId")
  public String getQueryId() {
    return queryId;
  }
  public void setQueryId(String queryId) {
    this.queryId = queryId;
  }

  

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TumorTypeQuery tumorTypeQuery = (TumorTypeQuery) o;
    return Objects.equals(queryType, tumorTypeQuery.queryType) &&
        Objects.equals(query, tumorTypeQuery.query) &&
        Objects.equals(queryId, tumorTypeQuery.queryId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(queryType, query, queryId);
  }

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class TumorTypeQuery {\n");
    
    sb.append("  queryType: ").append(queryType).append("\n");
    sb.append("  query: ").append(query).append("\n");
    sb.append("  queryId: ").append(queryId).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
