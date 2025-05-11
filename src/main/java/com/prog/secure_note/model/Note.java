package com.prog.secure_note.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Note {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //    The annotation @Lob in Java is used to indicate that the annotated field should be persisted as a Large Object in the database.
//    @Lob works with String, byte[], and some other types.
//    For String, it's mapped to a CLOB in the database.
//    For byte[], it's mapped to a BLOB (Binary Large Object).
//    So it is typically used for storing large text data such as articles, descriptions, or documents.
    @Lob
    private String content;

    private String ownerUsername;
}
