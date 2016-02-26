package org.mskcc.oncotree.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


@ApiModel(description = "")
@javax.annotation.Generated(value = "class io.swagger.codegen.languages.SpringMVCServerCodegen", date = "2016-02-24T17:47:20.686Z")
public class TumorType  {
  
  private String code = null;
  private String name = null;
  private String mainType = null;
  private String NCI = null;
  private String UMLS = null;
  private String color = null;
  private String parent = null;
  private List<String> children = new ArrayList<String>();

  
  /**
   * Unique identifier representing OncoKB tumor types.
   **/
  @ApiModelProperty(value = "Unique identifier representing OncoKB tumor types.")
  @JsonProperty("code")
  public String getCode() {
    return code;
  }
  public void setCode(String code) {
    this.code = code;
  }

  
  /**
   * Tumor type name.
   **/
  @ApiModelProperty(value = "Tumor type name.")
  @JsonProperty("name")
  public String getName() {
    return name;
  }
  public void setName(String name) {
    this.name = name;
  }

  
  /**
   * General tumor type category.
   **/
  @ApiModelProperty(value = "General tumor type category.")
  @JsonProperty("main_type")
  public String getMainType() {
    return mainType;
  }
  public void setMainType(String mainType) {
    this.mainType = mainType;
  }

  
  /**
   * NCI Thesaurus Code.
   **/
  @ApiModelProperty(value = "NCI Thesaurus Code.")
  @JsonProperty("NCI")
  public String getNCI() {
    return NCI;
  }
  public void setNCI(String NCI) {
    this.NCI = NCI;
  }

  
  /**
   * Concept Unique Identifier.
   **/
  @ApiModelProperty(value = "Concept Unique Identifier.")
  @JsonProperty("UMLS")
  public String getUMLS() {
    return UMLS;
  }
  public void setUMLS(String UMLS) {
    this.UMLS = UMLS;
  }

  
  /**
   * Tumor type color.
   **/
  @ApiModelProperty(value = "Tumor type color.")
  @JsonProperty("color")
  public String getColor() {
    return color;
  }
  public void setColor(String color) {
    this.color = color;
  }

  
  /**
   * Parent code.
   **/
  @ApiModelProperty(value = "Parent code.")
  @JsonProperty("parent")
  public String getParent() {
    return parent;
  }
  public void setParent(String parent) {
    this.parent = parent;
  }

  
  /**
   * List of all available children tumor types.
   **/
  @ApiModelProperty(value = "List of all available children tumor types.")
  @JsonProperty("children")
  public List<String> getChildren() {
    return children;
  }
  public void setChildren(List<String> children) {
    this.children = children;
  }

  

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TumorType tumorType = (TumorType) o;
    return Objects.equals(code, tumorType.code) &&
        Objects.equals(name, tumorType.name) &&
        Objects.equals(mainType, tumorType.mainType) &&
        Objects.equals(NCI, tumorType.NCI) &&
        Objects.equals(UMLS, tumorType.UMLS) &&
        Objects.equals(color, tumorType.color) &&
        Objects.equals(parent, tumorType.parent) &&
        Objects.equals(children, tumorType.children);
  }

  @Override
  public int hashCode() {
    return Objects.hash(code, name, mainType, NCI, UMLS, color, parent, children);
  }

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class TumorType {\n");
    
    sb.append("  code: ").append(code).append("\n");
    sb.append("  name: ").append(name).append("\n");
    sb.append("  mainType: ").append(mainType).append("\n");
    sb.append("  NCI: ").append(NCI).append("\n");
    sb.append("  UMLS: ").append(UMLS).append("\n");
    sb.append("  color: ").append(color).append("\n");
    sb.append("  parent: ").append(parent).append("\n");
    sb.append("  children: ").append(children).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
