//
//  ESODGroupAddEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
//

import Foundation
import CoreData


extension ESODGroupAddEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESODGroupAddEvent> {
        return NSFetchRequest<ESODGroupAddEvent>(entityName: "ESODGroupAddEvent")
    }

}

extension ESODGroupAddEvent : Identifiable {

}
