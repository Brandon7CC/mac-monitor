//
//  String+CapitalizedFirst.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Sentence case
extension String {
    /// The string with its first letter capitalized, as a sentence starts: "read and write" reads "Read and write".
    ///
    /// For text Mac Monitor puts together itself, such as a filter summary or a correlated event's access. Unlike
    /// `capitalized`, it leaves every other letter as it is.
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
